import {
  Notice,
  normalizePath,
  Plugin,
  WorkspaceLeaf
} from 'obsidian';
import { ComponentInventoryService } from './application/sbom/ComponentInventoryService';
import { ComponentPreferenceService } from './application/sbom/ComponentPreferenceService';
import { SbomCatalogService } from './application/sbom/SbomCatalogService';
import type { ComponentCatalog, ComponentInventorySnapshot } from './application/sbom/types';
import { AlertEngine } from './application/services/AlertEngine';
import { buildFeedsFromConfig } from './application/services/FeedFactory';
import { PollingOrchestrator } from './application/services/PollingOrchestrator';
import { SbomComparisonService, type SbomComparisonResult } from './application/services/SbomComparisonService';
import { SbomFilterMergeService } from './application/services/SbomFilterMergeService';
import {
  SbomImportService,
  type SbomFileChangeStatus,
  type SbomLoadResult,
  type SbomValidationResult
} from './application/services/SbomImportService';
import { buildFailureNoticeMessage, buildVisibilityDiagnostics, summarizeSyncResults } from './application/services/SyncOutcomeDiagnostics';
import type {
  ColumnVisibility,
  FeedConfig,
  ImportedSbomConfig,
  ResolvedSbomComponent,
  RuntimeSbomState,
  SbomComponentOverride,
  VulnDashSettings
} from './application/services/types';
import { buildSbomOverrideKey } from './application/services/types';
import type { Vulnerability } from './domain/entities/Vulnerability';
import { ProductNameNormalizer } from './domain/services/ProductNameNormalizer';
import { HttpClient } from './infrastructure/clients/common/HttpClient';
import { buildVulnerabilityNoteBody } from './infrastructure/obsidian/VulnerabilityNote';
import { VULNDASH_VIEW_TYPE, VulnDashView } from './infrastructure/obsidian/VulnDashView';
import { VulnDashSettingTab } from './infrastructure/obsidian/VulnDashSettingsTab';
import { decryptSecret, ENCRYPTED_SECRET_PREFIX, encryptSecret } from './infrastructure/utils/crypto';

interface LegacyImportedSbomComponent {
  bomRef?: unknown;
  cpe?: unknown;
  excluded?: unknown;
  name?: unknown;
  normalizedName?: unknown;
  purl?: unknown;
}

interface LegacyImportedSbomConfig extends Partial<ImportedSbomConfig> {
  components?: LegacyImportedSbomComponent[];
  lastImportError?: unknown;
  lastImportHash?: unknown;
}

const DEFAULT_COLUMN_VISIBILITY: ColumnVisibility = {
  id: true,
  title: true,
  source: true,
  severity: true,
  cvssScore: true,
  publishedAt: true
};

const DEFAULT_FEEDS: FeedConfig[] = [
  { id: 'nvd-default', name: 'NVD', type: 'nvd', enabled: true },
  { id: 'github-advisories-default', name: 'GitHub', type: 'github_advisory', enabled: true }
];

export const SETTINGS_VERSION = 5;

export const DEFAULT_SETTINGS: VulnDashSettings = {
  pollingIntervalMs: 60_000,
  pollOnStartup: true,
  keywordFilters: [],
  manualProductFilters: [],
  sbomFolders: [],
  followedSbomComponentKeys: [],
  disabledSbomComponentKeys: [],
  productFilters: [],
  minSeverity: 'MEDIUM',
  minCvssScore: 4.0,
  nvdApiKey: '',
  githubToken: '',
  systemNotificationsEnabled: true,
  desktopAlertsHighOrCritical: false,
  cacheDurationMs: 60_000,
  maxResults: 200,
  defaultSortOrder: 'publishedAt',
  colorCodedSeverity: true,
  columnVisibility: DEFAULT_COLUMN_VISIBILITY,
  keywordRegexEnabled: false,
  enableNvdFeed: true,
  enableGithubFeed: true,
  autoNoteCreationEnabled: false,
  autoHighNoteCreationEnabled: false,
  autoNoteFolder: 'VulnDash Alerts',
  sboms: [],
  sbomOverrides: {},
  sbomImportMode: 'append',
  sbomPath: '',
  syncControls: {
    maxPages: 10,
    maxItems: 500,
    retryCount: 3,
    backoffBaseMs: 1_000,
    overlapWindowMs: 180_000,
    bootstrapLookbackMs: 86_400_000,
    debugHttpMetadata: false
  },
  sourceSyncCursor: {},
  settingsVersion: SETTINGS_VERSION,
  feeds: DEFAULT_FEEDS.map((feed) => ({ ...feed }))
};

const legacyNameNormalizer = new ProductNameNormalizer();
const componentPreferenceService = new ComponentPreferenceService();

const cloneFeedConfig = (feed: FeedConfig): FeedConfig => ({ ...feed });

const normalizeStringList = (values: string[] | undefined): string[] => {
  if (!Array.isArray(values)) {
    return [];
  }

  return Array.from(new Set(values
    .map((value) => value.trim())
    .filter((value) => value.length > 0)));
};

const normalizePathList = (values: string[] | undefined): string[] => {
  if (!Array.isArray(values)) {
    return [];
  }

  return Array.from(new Set(values
    .map((value) => typeof value === 'string' ? normalizePath(value.trim()) : '')
    .filter((value) => value.length > 0)));
};

const areStringListsEqual = (left: string[], right: string[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const buildLegacySbomLabel = (path: string): string => {
  const normalized = normalizePath(path);
  const segments = normalized.split('/').filter(Boolean);
  const candidate = segments.at(-1);
  return candidate && candidate.length > 0 ? candidate : 'SBOM';
};

const getTrimmedString = (value: unknown): string => typeof value === 'string' ? value.trim() : '';

const normalizeImportedSbomConfig = (
  sbom: Partial<ImportedSbomConfig> & {
    componentCount?: unknown;
    lastError?: unknown;
    lastImportError?: unknown;
    lastImportHash?: unknown;
    lastImportedAt?: unknown;
  },
  index: number
): ImportedSbomConfig => {
  const namespace = getTrimmedString(sbom.namespace);
  const contentHash = getTrimmedString(sbom.contentHash) || getTrimmedString(sbom.lastImportHash);
  const lastError = getTrimmedString(sbom.lastError) || getTrimmedString(sbom.lastImportError);
  const componentCount = typeof sbom.componentCount === 'number' && Number.isFinite(sbom.componentCount) && sbom.componentCount >= 0
    ? sbom.componentCount
    : undefined;
  const lastImportedAt = typeof sbom.lastImportedAt === 'number' && Number.isFinite(sbom.lastImportedAt)
    ? sbom.lastImportedAt
    : 0;

  const normalized: ImportedSbomConfig = {
    contentHash,
    enabled: sbom.enabled ?? true,
    id: getTrimmedString(sbom.id) || `sbom-${index + 1}`,
    label: getTrimmedString(sbom.label) || buildLegacySbomLabel(getTrimmedString(sbom.path)),
    lastImportedAt,
    path: getTrimmedString(sbom.path) ? normalizePath(getTrimmedString(sbom.path)) : ''
  };

  if (namespace) {
    normalized.namespace = namespace;
  }
  if (componentCount !== undefined) {
    normalized.componentCount = componentCount;
  }
  if (lastError) {
    normalized.lastError = lastError;
  }

  return normalized;
};

const createLegacySbomConfig = (path: string): ImportedSbomConfig => {
  const normalizedPath = normalizePath(path);
  return {
    contentHash: '',
    enabled: true,
    id: 'sbom-1',
    label: buildLegacySbomLabel(normalizedPath),
    lastImportedAt: 0,
    path: normalizedPath
  };
};

const normalizeSbomOverride = (override: Partial<SbomComponentOverride>): SbomComponentOverride | null => {
  const editedName = getTrimmedString(override.editedName);
  const excluded = override.excluded === true;
  const normalized: SbomComponentOverride = {};

  if (editedName) {
    normalized.editedName = editedName;
  }
  if (excluded) {
    normalized.excluded = true;
  }

  return Object.keys(normalized).length > 0 ? normalized : null;
};

const normalizeSbomOverrides = (overrides: Record<string, SbomComponentOverride> | undefined): Record<string, SbomComponentOverride> => {
  if (!overrides || typeof overrides !== 'object') {
    return {};
  }

  const normalizedEntries = Object.entries(overrides).flatMap(([key, value]) => {
    const override = normalizeSbomOverride(value);
    return override ? [[key, override] as const] : [];
  });

  return Object.fromEntries(normalizedEntries);
};

const migrateLegacySbomOverrides = (sboms: LegacyImportedSbomConfig[]): Record<string, SbomComponentOverride> => {
  const overrides: Record<string, SbomComponentOverride> = {};

  for (const [index, sbom] of sboms.entries()) {
    const normalizedSbom = normalizeImportedSbomConfig(sbom, index);
    const components = Array.isArray(sbom.components) ? sbom.components : [];

    for (const component of components) {
      const originalName = getTrimmedString(component.name)
        || getTrimmedString(component.normalizedName)
        || getTrimmedString(component.cpe)
        || getTrimmedString(component.purl)
        || getTrimmedString(component.bomRef);
      if (!originalName) {
        continue;
      }

      const editedName = getTrimmedString(component.normalizedName);
      const defaultName = legacyNameNormalizer.normalize(originalName) || originalName;
      const overrideInput: Partial<SbomComponentOverride> = {
        excluded: component.excluded === true
      };
      if (editedName && editedName !== defaultName) {
        overrideInput.editedName = editedName;
      }
      const override = normalizeSbomOverride(overrideInput);
      if (!override) {
        continue;
      }

      overrides[buildSbomOverrideKey(normalizedSbom.id, originalName)] = override;
    }
  }

  return overrides;
};

const normalizeRuntimeSettings = (settings: VulnDashSettings): VulnDashSettings => ({
  ...componentPreferenceService.normalizeSettings(settings),
  keywordFilters: normalizeStringList(settings.keywordFilters),
  manualProductFilters: normalizeStringList(settings.manualProductFilters),
  productFilters: normalizeStringList(settings.productFilters),
  sbomFolders: normalizePathList(settings.sbomFolders),
  sboms: settings.sboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index)),
  sbomOverrides: normalizeSbomOverrides(settings.sbomOverrides),
  sbomPath: '',
  settingsVersion: SETTINGS_VERSION
});

export const migrateLegacySettings = (settings: Partial<VulnDashSettings> & { sboms?: LegacyImportedSbomConfig[] }): VulnDashSettings => {
  const hasDynamicFeeds = Array.isArray(settings.feeds) && settings.feeds.length > 0;
  const feeds = hasDynamicFeeds
    ? (settings.feeds ?? []).map((feed) => cloneFeedConfig(feed))
    : DEFAULT_FEEDS.map((feed) => cloneFeedConfig(feed));

  if (!hasDynamicFeeds) {
    const nvdFeed = feeds.find((feed): feed is Extract<FeedConfig, { type: 'nvd' }> => feed.type === 'nvd' && feed.id === 'nvd-default');
    if (nvdFeed && settings.nvdApiKey) {
      nvdFeed.apiKey = settings.nvdApiKey;
    }
    if (typeof settings.enableNvdFeed === 'boolean' && nvdFeed) {
      nvdFeed.enabled = settings.enableNvdFeed;
    }

    const githubFeed = feeds.find((feed) => feed.type === 'github_advisory' && feed.id === 'github-advisories-default');
    if (githubFeed && settings.githubToken) {
      githubFeed.token = settings.githubToken;
    }
    if (typeof settings.enableGithubFeed === 'boolean' && githubFeed) {
      githubFeed.enabled = settings.enableGithubFeed;
    }
  }

  const cursor = { ...(settings.sourceSyncCursor ?? {}) };
  const legacyNvdCursor = cursor.NVD;
  const legacyGithubCursor = cursor.GitHub;
  if (legacyNvdCursor && !cursor['nvd-default']) {
    cursor['nvd-default'] = legacyNvdCursor;
  }
  if (legacyGithubCursor && !cursor['github-advisories-default']) {
    cursor['github-advisories-default'] = legacyGithubCursor;
  }
  delete cursor.NVD;
  delete cursor.GitHub;

  const isCurrentSettingsVersion = (settings.settingsVersion ?? 0) >= SETTINGS_VERSION;
  const legacyProductFilters = normalizeStringList(settings.productFilters);
  const manualProductFilters = normalizeStringList(isCurrentSettingsVersion
    ? settings.manualProductFilters
    : (settings.manualProductFilters ?? legacyProductFilters));
  const productFilters = normalizeStringList(isCurrentSettingsVersion
    ? (settings.productFilters ?? [])
    : manualProductFilters);

  const rawSboms = Array.isArray(settings.sboms) ? settings.sboms : [];
  const sboms = rawSboms.length > 0
    ? rawSboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index))
    : (settings.sbomPath?.trim()
      ? [createLegacySbomConfig(settings.sbomPath)]
      : []);

  const migratedOverrides = migrateLegacySbomOverrides(rawSboms);
  const sbomOverrides = normalizeSbomOverrides({
    ...migratedOverrides,
    ...(settings.sbomOverrides ?? {})
  });

  return normalizeRuntimeSettings({
    ...DEFAULT_SETTINGS,
    ...settings,
    manualProductFilters,
    productFilters,
    sboms,
    sbomOverrides,
    settingsVersion: SETTINGS_VERSION,
    feeds,
    sourceSyncCursor: cursor,
    columnVisibility: {
      ...DEFAULT_COLUMN_VISIBILITY,
      ...(settings.columnVisibility ?? {})
    },
    syncControls: {
      ...DEFAULT_SETTINGS.syncControls,
      ...(settings.syncControls ?? {})
    }
  });
};

const createEmptySbomConfig = (index: number): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: `sbom-${Date.now()}-${index + 1}`,
  label: `SBOM ${index + 1}`,
  lastImportedAt: 0,
  path: ''
});

export const buildPersistedSettingsSnapshot = (
  settings: VulnDashSettings,
  secrets: {
    githubToken: string;
    nvdApiKey: string;
  },
  feeds: FeedConfig[]
): VulnDashSettings => ({
  ...componentPreferenceService.normalizeSettings(settings),
  sbomOverrides: normalizeSbomOverrides(settings.sbomOverrides),
  sbomFolders: normalizePathList(settings.sbomFolders),
  sbomPath: '',
  settingsVersion: SETTINGS_VERSION,
  nvdApiKey: secrets.nvdApiKey,
  githubToken: secrets.githubToken,
  feeds
});

export default class VulnDashPlugin extends Plugin {
  private settings: VulnDashSettings = DEFAULT_SETTINGS;
  private stopPolling: (() => void) | null = null;
  private pollingEnabled = false;
  private readonly alertEngine = new AlertEngine();
  private readonly componentInventoryService = new ComponentInventoryService();
  private readonly componentPreferenceService = componentPreferenceService;
  private readonly sbomCatalogService = new SbomCatalogService();
  private readonly sbomComparisonService = new SbomComparisonService();
  private readonly sbomFilterMergeService = new SbomFilterMergeService();
  private sbomImportService: SbomImportService | null = null;
  private lastFetchAt = 0;
  private cachedVulnerabilities: Vulnerability[] = [];
  private previousVisibleIds = new Set<string>();

  public override async onload(): Promise<void> {
    await this.loadSettings();
    await this.recomputeFilters();

    this.registerView(VULNDASH_VIEW_TYPE, (leaf) =>
      new VulnDashView(
        leaf,
        async () => {
          await this.refreshNow();
        },
        async () => this.togglePolling(),
        () => this.pollingEnabled,
        {
          disableComponent: async (componentKey) => this.disableSbomComponent(componentKey),
          enableComponent: async (componentKey) => this.enableSbomComponent(componentKey),
          followComponent: async (componentKey) => this.followSbomComponent(componentKey),
          loadComponentInventory: async () => this.getComponentInventorySnapshot(),
          unfollowComponent: async (componentKey) => this.unfollowSbomComponent(componentKey)
        }
      )
    );

    this.addRibbonIcon('shield-alert', 'Open VulnDash', () => {
      void this.activateView();
    });

    this.addCommand({
      id: 'vulndash-open',
      name: 'Open vulnerability dashboard',
      callback: () => {
        void this.activateView();
      }
    });

    this.addSettingTab(new VulnDashSettingTab(this.app, this));

    if (this.settings.pollOnStartup) {
      this.startPolling();
    }
    await this.activateView();
  }

  public override onunload(): void {
    this.stopPollingLoop();
  }

  public async refreshNow(): Promise<void> {
    const now = Date.now();
    const cacheValid = now - this.lastFetchAt <= this.settings.cacheDurationMs;
    if (cacheValid && this.cachedVulnerabilities.length > 0) {
      await this.processData(this.cachedVulnerabilities);
      return;
    }

    const orchestrator = this.createOrchestrator();
    try {
      const outcome = await orchestrator.pollOnce();
      const syncSummaries = summarizeSyncResults(outcome.results);
      for (const summary of syncSummaries) {
        console.info('[vulndash.sync.feed_summary]', summary);
      }
      const failureNotice = buildFailureNoticeMessage(outcome.results);
      if (failureNotice) {
        new Notice(failureNotice);
      }
      this.cachedVulnerabilities = outcome.vulnerabilities;
      this.settings.sourceSyncCursor = outcome.sourceSyncCursor;
      await this.saveSettings();
      this.lastFetchAt = Date.now();
      await this.processData(outcome.vulnerabilities);
    } catch {
      new Notice('VulnDash refresh failed. Check your network or API tokens.');
    }
  }

  public async updateSettings(next: VulnDashSettings): Promise<void> {
    await this.applySettings(next, { refetchRemoteData: true, restartPolling: true });
  }

  public async updateLocalSettings(next: VulnDashSettings): Promise<void> {
    await this.applySettings(next, { recomputeFilters: true });
  }

  public getSettings(): VulnDashSettings {
    return this.settings;
  }

  public async togglePolling(): Promise<void> {
    if (this.pollingEnabled) {
      this.stopPollingLoop();
      this.updateViewPollingState();
      return;
    }

    this.startPolling();
    this.updateViewPollingState();
    await this.refreshNow();
  }

  public async importProductFiltersFromSbom(): Promise<void> {
    new Notice('Legacy SBOM import has been retired. Configure SBOM entries under the multi-SBOM management flow.');
  }

  public async addSbom(): Promise<ImportedSbomConfig> {
    const createdSbom = createEmptySbomConfig(this.settings.sboms.length);
    const nextSboms = [...this.settings.sboms, createdSbom];
    await this.applySettings({ ...this.settings, sboms: nextSboms });
    return createdSbom;
  }

  public async removeSbom(sbomId: string): Promise<void> {
    this.getSbomImportService().invalidateCache(sbomId);

    const nextSboms = this.settings.sboms.filter((sbom) => sbom.id !== sbomId);
    const nextOverrides = Object.fromEntries(Object.entries(this.settings.sbomOverrides)
      .filter(([key]) => !key.startsWith(`${sbomId}::`)));

    await this.applySettings({
      ...this.settings,
      sbomOverrides: nextOverrides,
      sboms: nextSboms
    }, { recomputeFilters: true });
  }

  public async updateSbomConfig(sbomId: string, updates: Partial<ImportedSbomConfig>): Promise<void> {
    const current = this.getSbomById(sbomId);
    if (!current) {
      return;
    }

    const nextSboms = this.settings.sboms.map((sbom, index) => (
      sbom.id === sbomId
        ? normalizeImportedSbomConfig({
          ...sbom,
          ...updates
        }, index)
        : sbom
    ));

    if (typeof updates.path === 'string' && normalizePath(updates.path || '') !== normalizePath(current.path || '')) {
      this.getSbomImportService().invalidateCache(sbomId);
    }

    const shouldRecompute = updates.enabled !== undefined || updates.path !== undefined;
    await this.applySettings({ ...this.settings, sboms: nextSboms }, { recomputeFilters: shouldRecompute });
  }

  public async updateSbomComponentOverride(
    sbomId: string,
    originalName: string,
    updates: Partial<SbomComponentOverride>
  ): Promise<void> {
    const overrideKey = buildSbomOverrideKey(sbomId, originalName);
    const nextOverrides = { ...this.settings.sbomOverrides };
    const mergedOverride = normalizeSbomOverride({
      ...(nextOverrides[overrideKey] ?? {}),
      ...updates
    });

    if (mergedOverride) {
      nextOverrides[overrideKey] = mergedOverride;
    } else {
      delete nextOverrides[overrideKey];
    }

    await this.applySettings({
      ...this.settings,
      sbomOverrides: nextOverrides
    }, { recomputeFilters: true });
  }

  public async removeSbomComponent(sbomId: string, originalName: string): Promise<void> {
    await this.updateSbomComponentOverride(sbomId, originalName, { excluded: true });
  }

  public async recomputeFilters(): Promise<void> {
    const loadResults = await this.getSbomImportService().loadAllSboms(this.settings);
    const mergedSettings = this.applySbomLoadResults(this.settings, loadResults);
    const nextSettings = normalizeRuntimeSettings({
      ...mergedSettings,
      productFilters: this.sbomFilterMergeService.merge(
        mergedSettings,
        this.getSbomImportService().getRuntimeCacheSnapshot()
      )
    });
    const filtersChanged = !areStringListsEqual(nextSettings.productFilters, this.settings.productFilters);
    const sbomsChanged = JSON.stringify(nextSettings.sboms) !== JSON.stringify(this.settings.sboms);

    this.settings = nextSettings;
    if (filtersChanged || sbomsChanged) {
      await this.saveSettings();
    }

    this.updateViewSettings();
    this.updateViewPollingState();
    await this.processData(this.cachedVulnerabilities);
  }

  public async syncSbom(sbomId: string): Promise<{ message: string; success: boolean }> {
    const sbom = this.settings.sboms.find((entry) => entry.id === sbomId);
    if (!sbom) {
      return { message: 'SBOM entry was not found.', success: false };
    }

    const result = await this.getSbomImportService().loadSbom(sbom, { force: true });
    const nextSettings = {
      ...this.settings,
      sboms: this.settings.sboms.map((entry, index) => (
        entry.id === sbomId
          ? this.applySbomLoadResultToConfig(entry, result, index)
          : entry
      ))
    };

    await this.applySettings(nextSettings, { recomputeFilters: sbom.enabled });

    if (!result.success) {
      return { message: result.error, success: false };
    }

    return {
      message: `Loaded ${result.state.components.length} components from ${sbom.label}.`,
      success: true
    };
  }

  public async syncAllSboms(): Promise<{ failed: number; succeeded: number; total: number }> {
    const results = await Promise.all(this.settings.sboms.map(async (sbom) => [sbom.id, await this.getSbomImportService().loadSbom(sbom, { force: true })] as const));
    const resultMap = new Map(results);
    let succeeded = 0;
    let failed = 0;

    for (const result of resultMap.values()) {
      if (result.success) {
        succeeded += 1;
      } else {
        failed += 1;
      }
    }

    const nextSettings = {
      ...this.settings,
      sboms: this.settings.sboms.map((sbom, index) => this.applySbomLoadResultToConfig(sbom, resultMap.get(sbom.id) ?? null, index))
    };

    await this.applySettings(nextSettings, { recomputeFilters: true });
    return {
      failed,
      succeeded,
      total: this.settings.sboms.length
    };
  }

  public async getSbomFileChangeStatus(sbomId: string): Promise<SbomFileChangeStatus> {
    const sbom = this.settings.sboms.find((entry) => entry.id === sbomId);
    if (!sbom) {
      return {
        currentHash: null,
        error: 'SBOM entry was not found.',
        status: 'error'
      };
    }

    return this.getSbomImportService().getFileChangeStatus(sbom);
  }

  public async getSbomFileStatuses(): Promise<Map<string, SbomFileChangeStatus>> {
    const entries = await Promise.all(this.settings.sboms.map(async (sbom) => (
      [sbom.id, await this.getSbomImportService().getFileChangeStatus(sbom)] as const
    )));

    return new Map(entries);
  }

  public async validateSbomPath(path: string): Promise<SbomValidationResult> {
    return this.getSbomImportService().validateSbomPath(path);
  }

  public getSbomById(sbomId: string): ImportedSbomConfig | undefined {
    return this.settings.sboms.find((sbom) => sbom.id === sbomId);
  }

  public isSbomComponentFollowed(componentKey: string): boolean {
    return this.componentPreferenceService.isFollowed(componentKey, this.settings);
  }

  public isSbomComponentEnabled(componentKey: string): boolean {
    return this.componentPreferenceService.isEnabled(componentKey, this.settings);
  }

  public async followSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.componentPreferenceService.follow(componentKey, this.settings));
  }

  public async unfollowSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.componentPreferenceService.unfollow(componentKey, this.settings));
  }

  public async disableSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.componentPreferenceService.disable(componentKey, this.settings));
  }

  public async enableSbomComponent(componentKey: string): Promise<void> {
    await this.applySettings(this.componentPreferenceService.enable(componentKey, this.settings));
  }

  public async getSbomCatalog(): Promise<ComponentCatalog> {
    const loadResults = await this.getSbomImportService().loadAllSboms(this.settings);
    const catalog = this.sbomCatalogService.buildCatalog(this.collectCatalogDocuments(loadResults));
    return this.componentPreferenceService.applyPreferences(catalog, this.settings);
  }

  public async getComponentInventorySnapshot(): Promise<ComponentInventorySnapshot> {
    const loadResults = await this.getSbomImportService().loadAllSboms(this.settings);
    return this.componentInventoryService.buildSnapshot(this.settings, loadResults);
  }

  public async getSbomComponents(sbomId: string): Promise<ResolvedSbomComponent[] | null> {
    const sbom = this.getSbomById(sbomId);
    if (!sbom) {
      return null;
    }

    const runtimeState = await this.ensureSbomRuntimeState(sbom);
    return this.sbomFilterMergeService.getResolvedComponents(sbom, runtimeState, this.settings.sbomOverrides);
  }

  public async compareSboms(leftSbomId: string, rightSbomId: string): Promise<SbomComparisonResult | null> {
    const [leftComponents, rightComponents] = await Promise.all([
      this.getSbomComponents(leftSbomId),
      this.getSbomComponents(rightSbomId)
    ]);

    if (!leftComponents || !rightComponents) {
      return null;
    }

    return this.sbomComparisonService.compare(
      leftComponents.filter((component) => !component.excluded).map((component) => component.displayName),
      rightComponents.filter((component) => !component.excluded).map((component) => component.displayName)
    );
  }

  public getSbomRuntimeState(sbomId: string): RuntimeSbomState | null {
    return this.getSbomImportService().getRuntimeState(sbomId);
  }

  private async ensureSbomRuntimeState(sbom: ImportedSbomConfig): Promise<RuntimeSbomState | null> {
    const result = await this.getSbomImportService().loadSbom(sbom);
    if (result.success) {
      return result.state;
    }

    return result.cachedState;
  }

  private collectCatalogDocuments(results: readonly SbomLoadResult[]): RuntimeSbomState['document'][] {
    return results.flatMap((result) => {
      if (result.success) {
        return [result.state.document];
      }

      return result.cachedState ? [result.cachedState.document] : [];
    });
  }

  private applySbomLoadResults(settings: VulnDashSettings, results: SbomLoadResult[]): VulnDashSettings {
    const resultMap = new Map(results.map((result) => [result.sbomId, result] as const));

    return {
      ...settings,
      sboms: settings.sboms.map((sbom, index) => this.applySbomLoadResultToConfig(sbom, resultMap.get(sbom.id) ?? null, index))
    };
  }

  private applySbomLoadResultToConfig(
    sbom: ImportedSbomConfig,
    result: SbomLoadResult | null,
    index: number
  ): ImportedSbomConfig {
    if (!result) {
      return normalizeImportedSbomConfig(sbom, index);
    }

    if (!result.success) {
      return normalizeImportedSbomConfig({
        ...sbom,
        lastError: result.error
      }, index);
    }

    return normalizeImportedSbomConfig({
      ...sbom,
      componentCount: result.state.components.length,
      contentHash: result.state.hash,
      lastError: '',
      lastImportedAt: result.state.lastLoadedAt,
      path: result.state.sourcePath
    }, index);
  }

  private async processData(vulnerabilities: Vulnerability[]): Promise<void> {
    const filtered = this.alertEngine.filter(vulnerabilities, this.settings);
    const diagnostics = buildVisibilityDiagnostics(vulnerabilities, filtered);
    console.info('[vulndash.filter.visibility]', diagnostics);
    this.updateView(filtered);
    await this.notifyOnNewItems(filtered);
  }

  private async notifyOnNewItems(vulnerabilities: Vulnerability[]): Promise<void> {
    const current = new Set(vulnerabilities.map((vulnerability) => `${vulnerability.source}:${vulnerability.id}`));
    const newItems = vulnerabilities.filter((vulnerability) => !this.previousVisibleIds.has(`${vulnerability.source}:${vulnerability.id}`));
    this.previousVisibleIds = current;

    if (newItems.length === 0) {
      return;
    }

    if (this.settings.systemNotificationsEnabled) {
      new Notice(`VulnDash detected ${newItems.length} new matching vulnerabilities.`);
    }

    const highPriority = newItems.filter((vulnerability) =>
      vulnerability.severity === 'CRITICAL' || vulnerability.severity === 'HIGH'
    );

    if (this.settings.desktopAlertsHighOrCritical) {
      this.sendDesktopAlert(highPriority);
    }

    if (this.settings.autoNoteCreationEnabled || this.settings.autoHighNoteCreationEnabled) {
      await this.createSeverityNotes(newItems.filter((vulnerability) =>
        vulnerability.severity === 'CRITICAL'
        || (this.settings.autoHighNoteCreationEnabled && vulnerability.severity === 'HIGH')
      ));
    }
  }

  private sendDesktopAlert(vulnerabilities: Vulnerability[]): void {
    if (vulnerabilities.length === 0) {
      return;
    }

    if (!('Notification' in window)) {
      return;
    }

    if (Notification.permission === 'granted') {
      const top = vulnerabilities[0];
      if (!top) {
        return;
      }
      new Notification('VulnDash high-severity alert', {
        body: `${vulnerabilities.length} HIGH/CRITICAL issue(s). Latest: ${top.id}`
      });
      return;
    }

    if (Notification.permission === 'default') {
      void Notification.requestPermission();
    }
  }

  private async createSeverityNotes(vulnerabilities: Vulnerability[]): Promise<void> {
    if (vulnerabilities.length === 0) {
      return;
    }

    await this.ensureFolder(this.settings.autoNoteFolder);

    for (const vulnerability of vulnerabilities) {
      const safeId = vulnerability.id.replace(/[^A-Za-z0-9._-]/g, '-');
      const notePath = normalizePath(`${this.settings.autoNoteFolder}/${safeId}.md`);
      const exists = await this.app.vault.adapter.exists(notePath);
      if (exists) {
        continue;
      }

      await this.app.vault.create(notePath, buildVulnerabilityNoteBody(vulnerability));
    }
  }

  private async ensureFolder(folderPath: string): Promise<void> {
    const cleanPath = normalizePath(folderPath);
    if (!cleanPath || cleanPath === '/') {
      return;
    }

    if (await this.app.vault.adapter.exists(cleanPath)) {
      return;
    }

    const parts = cleanPath.split('/').filter(Boolean);
    let current = '';
    for (const part of parts) {
      current = current ? `${current}/${part}` : part;
      const exists = await this.app.vault.adapter.exists(current);
      if (!exists) {
        await this.app.vault.createFolder(current);
      }
    }
  }

  private startPolling(): void {
    if (this.pollingEnabled) {
      return;
    }

    const orchestrator = this.createOrchestrator();
    this.pollingEnabled = true;
    this.stopPolling = orchestrator.start(this.settings.pollingIntervalMs, (outcome) => {
      this.cachedVulnerabilities = outcome.vulnerabilities;
      this.settings.sourceSyncCursor = outcome.sourceSyncCursor;
      void this.saveSettings();
      this.lastFetchAt = Date.now();
      void this.processData(outcome.vulnerabilities);
    });
  }

  private restartPolling(): void {
    const wasPolling = this.pollingEnabled;
    this.stopPollingLoop();
    if (wasPolling || this.settings.pollOnStartup) {
      this.startPolling();
    }
  }

  private stopPollingLoop(): void {
    if (this.stopPolling) {
      this.stopPolling();
      this.stopPolling = null;
    }
    this.pollingEnabled = false;
  }

  private createOrchestrator(): PollingOrchestrator {
    const client = new HttpClient();
    const feeds = buildFeedsFromConfig(this.settings.feeds, client, this.settings.syncControls);

    return new PollingOrchestrator(feeds, this.settings.syncControls, {
      cache: this.cachedVulnerabilities,
      sourceSyncCursor: this.settings.sourceSyncCursor
    });
  }

  private updateViewPollingState(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setPollingEnabled(this.pollingEnabled);
      }
    }
  }

  private updateView(vulnerabilities: Vulnerability[]): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setData(vulnerabilities);
      }
    }
  }

  private updateViewSettings(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setSettings(this.settings);
      }
    }
  }

  private async activateView(): Promise<void> {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    let leaf: WorkspaceLeaf | null = leaves[0] ?? null;

    if (!leaf) {
      leaf = this.app.workspace.getLeaf(true);
      await leaf.setViewState({
        type: VULNDASH_VIEW_TYPE,
        active: true
      });
    }

    this.app.workspace.revealLeaf(leaf);
    this.updateViewSettings();
    this.updateViewPollingState();
    await this.refreshNow();
  }

  private async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    const loadedSettings = (loaded as (Partial<VulnDashSettings> & { sboms?: LegacyImportedSbomConfig[] }) | null) ?? null;
    const loadedNvd = loadedSettings?.nvdApiKey ?? '';
    const loadedGithub = loadedSettings?.githubToken ?? '';
    const nvdSecret = await this.loadSecret(loadedNvd);
    const githubSecret = await this.loadSecret(loadedGithub);

    const loadedFeeds = await Promise.all((loadedSettings?.feeds ?? []).map(async (feed) => {
      if (feed.type === 'nvd') {
        const apiKeySecret = await this.loadSecret(feed.apiKey ?? '');
        return {
          ...feed,
          apiKey: apiKeySecret.value
        };
      }

      const tokenSecret = await this.loadSecret(feed.token ?? '');
      return {
        ...feed,
        token: tokenSecret.value
      };
    }));

    const migrated = migrateLegacySettings({
      ...(loadedSettings ?? {}),
      nvdApiKey: nvdSecret.value,
      githubToken: githubSecret.value,
      feeds: loadedFeeds
    });
    this.settings = migrated;

    if (nvdSecret.decryptionFailed || githubSecret.decryptionFailed) {
      new Notice('VulnDash could not decrypt one or more stored API keys. Please re-enter your keys.');
    }

    if (nvdSecret.needsMigration || githubSecret.needsMigration || (loadedSettings?.settingsVersion ?? 0) < SETTINGS_VERSION) {
      await this.saveSettings();
    }
  }

  private async saveSettings(): Promise<void> {
    const encryptedNvd = await this.serializeSecret(this.settings.nvdApiKey);
    const encryptedGithub = await this.serializeSecret(this.settings.githubToken);
    const feeds = await Promise.all(this.settings.feeds.map(async (feed) => {
      if (feed.type === 'nvd') {
        return {
          ...feed,
          apiKey: await this.serializeSecret(feed.apiKey ?? '')
        };
      }
      if (feed.token) {
        return {
          ...feed,
          token: await this.serializeSecret(feed.token)
        };
      }
      return { ...feed };
    }));

    const dataToSave = buildPersistedSettingsSnapshot(this.settings, {
      githubToken: encryptedGithub,
      nvdApiKey: encryptedNvd
    }, feeds);

    await this.saveData(dataToSave);
  }

  private async serializeSecret(secret: string): Promise<string> {
    if (!secret) {
      return '';
    }
    const encrypted = await encryptSecret(secret);
    if (!encrypted) {
      return '';
    }
    return `${ENCRYPTED_SECRET_PREFIX}${encrypted}`;
  }

  private async loadSecret(secret: string): Promise<{ value: string; needsMigration: boolean; decryptionFailed: boolean }> {
    if (!secret) {
      return { value: '', needsMigration: false, decryptionFailed: false };
    }

    if (!secret.startsWith(ENCRYPTED_SECRET_PREFIX)) {
      return { value: secret, needsMigration: true, decryptionFailed: false };
    }

    const encryptedPayload = secret.slice(ENCRYPTED_SECRET_PREFIX.length);
    const decrypted = await decryptSecret(encryptedPayload);
    if (decrypted.status === 'success') {
      return { value: decrypted.value, needsMigration: false, decryptionFailed: false };
    }

    return { value: '', needsMigration: false, decryptionFailed: true };
  }

  private async applySettings(
    next: VulnDashSettings,
    options: {
      recomputeFilters?: boolean;
      refetchRemoteData?: boolean;
      restartPolling?: boolean;
    } = {}
  ): Promise<void> {
    this.settings = normalizeRuntimeSettings(next);
    await this.saveSettings();

    if (options.restartPolling) {
      this.restartPolling();
    }

    this.updateViewSettings();
    this.updateViewPollingState();

    if (options.recomputeFilters) {
      await this.recomputeFilters();
      return;
    }

    if (options.refetchRemoteData) {
      await this.refreshNow();
      return;
    }

    await this.processData(this.cachedVulnerabilities);
  }

  private getSbomImportService(): SbomImportService {
    if (!this.sbomImportService) {
      this.sbomImportService = new SbomImportService(this.app.vault.adapter);
    }
    return this.sbomImportService;
  }
}
