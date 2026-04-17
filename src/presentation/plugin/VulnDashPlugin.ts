import {
  Notice,
  normalizePath,
  Plugin,
  TAbstractFile,
  TFile,
  WorkspaceLeaf
} from 'obsidian';
import { ComponentBacklinkService } from '../../application/sbom/ComponentBacklinkService';
import { ComponentInventoryService } from '../../application/sbom/ComponentInventoryService';
import { ComponentPreferenceService } from '../../application/sbom/ComponentPreferenceService';
import { ComponentVulnerabilityLinkService } from '../../application/sbom/ComponentVulnerabilityLinkService';
import { RelationshipNormalizer } from '../../application/sbom/RelationshipNormalizer';
import { SbomCatalogService } from '../../application/sbom/SbomCatalogService';
import type {
  ComponentCatalog,
  ComponentInventorySnapshot,
  ComponentInventoryWorkspaceSnapshot
} from '../../application/sbom/types';
import { AlertEngine } from '../../application/use-cases/EvaluateAlertsUseCase';
import type { PipelineEvent } from '../../application/pipeline/PipelineEvents';
import type { ChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import { buildVulnerabilityCacheKey, createEmptyChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import { buildFeedsFromConfig } from '../../infrastructure/factories/FeedFactory';
import { SbomComparisonService, type SbomComparisonResult } from '../../application/use-cases/SbomComparisonService';
import { SbomFilterMergeService } from '../../application/use-cases/SbomFilterMergeService';
import {
  SbomImportService,
  type SbomFileChangeStatus,
  type SbomLoadResult,
  type SbomValidationResult
} from '../../application/use-cases/SbomImportService';
import { buildFailureNoticeMessage, buildVisibilityDiagnostics, summarizeSyncResults } from '../../application/use-cases/SyncOutcomeDiagnostics';
import { VulnerabilitySyncService, type SyncOutcome } from '../../application/use-cases/SyncVulnerabilitiesUseCase';
import type {
  ColumnVisibility,
  FeedConfig,
  ImportedSbomConfig,
  CacheStorageSettings,
  ResolvedSbomComponent,
  RuntimeSbomState,
  SbomComponentOverride,
  VulnDashSettings
} from '../../application/use-cases/types';
import { buildSbomOverrideKey } from '../../application/use-cases/types';
import { JoinTriageState, type JoinedTriageVulnerability } from '../../application/triage/JoinTriageState';
import { SetTriageState } from '../../application/triage/SetTriageState';
import { normalizeTriageFilterMode } from '../../application/triage/FilterByTriageState';
import { buildTriageCorrelationKeyForVulnerability } from '../../domain/triage/TriageCorrelation';
import type { TriageRecord } from '../../domain/triage/TriageRecord';
import { DEFAULT_TRIAGE_STATE, type TriageState } from '../../domain/triage/TriageState';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import { HttpClient } from '../../infrastructure/clients/common/HttpClient';
import { CooperativeScheduler } from '../../infrastructure/async/CooperativeScheduler';
import { CacheHydrator } from '../../infrastructure/storage/CacheHydrator';
import { CachePruner } from '../../infrastructure/storage/CachePruner';
import { IndexedDbTriageRepository } from '../../infrastructure/storage/IndexedDbTriageRepository';
import { LegacyDataMigration, type LegacyPersistedPluginData } from '../../infrastructure/storage/LegacyDataMigration';
import { SyncMetadataRepository } from '../../infrastructure/storage/SyncMetadataRepository';
import { VulnCacheDb } from '../../infrastructure/storage/VulnCacheDb';
import { VulnCacheRepository } from '../../infrastructure/storage/VulnCacheRepository';
import { buildVulnerabilityNoteBody } from '../../infrastructure/obsidian-adapters/VulnerabilityNote';
import { ComponentNoteResolverFactory } from '../../infrastructure/obsidian-adapters/ObsidianNoteResolver';
import { VULNDASH_VIEW_TYPE, VulnDashView } from '../views/VulnDashView';
import { VulnDashSettingTab } from '../settings/VulnDashSettingsTab';
import { decryptSecret, ENCRYPTED_SECRET_PREFIX, encryptSecret } from '../../infrastructure/security/crypto';

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

const DEFAULT_CACHE_STORAGE: CacheStorageSettings = {
  hardCap: 5000,
  hydrateMaxItems: 1000,
  hydratePageSize: 200,
  pruneBatchSize: 250,
  ttlMs: 30 * 24 * 60 * 60 * 1000
};

export const SETTINGS_VERSION = 6;

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
  triageFilter: 'all',
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
  cacheStorage: DEFAULT_CACHE_STORAGE,
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

const normalizeCacheStorage = (value: Partial<CacheStorageSettings> | undefined): CacheStorageSettings => ({
  hardCap: typeof value?.hardCap === 'number' && Number.isFinite(value.hardCap) && value.hardCap > 0 ? Math.floor(value.hardCap) : DEFAULT_CACHE_STORAGE.hardCap,
  hydrateMaxItems: typeof value?.hydrateMaxItems === 'number' && Number.isFinite(value.hydrateMaxItems) && value.hydrateMaxItems > 0 ? Math.floor(value.hydrateMaxItems) : DEFAULT_CACHE_STORAGE.hydrateMaxItems,
  hydratePageSize: typeof value?.hydratePageSize === 'number' && Number.isFinite(value.hydratePageSize) && value.hydratePageSize > 0 ? Math.floor(value.hydratePageSize) : DEFAULT_CACHE_STORAGE.hydratePageSize,
  pruneBatchSize: typeof value?.pruneBatchSize === 'number' && Number.isFinite(value.pruneBatchSize) && value.pruneBatchSize > 0 ? Math.floor(value.pruneBatchSize) : DEFAULT_CACHE_STORAGE.pruneBatchSize,
  ttlMs: typeof value?.ttlMs === 'number' && Number.isFinite(value.ttlMs) && value.ttlMs > 0 ? Math.floor(value.ttlMs) : DEFAULT_CACHE_STORAGE.ttlMs
});

const normalizeRuntimeSettings = (settings: VulnDashSettings): VulnDashSettings => ({
  ...componentPreferenceService.normalizeSettings(settings),
  keywordFilters: normalizeStringList(settings.keywordFilters),
  manualProductFilters: normalizeStringList(settings.manualProductFilters),
  productFilters: normalizeStringList(settings.productFilters),
  sbomFolders: normalizePathList(settings.sbomFolders),
  sboms: settings.sboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index)),
  sbomOverrides: normalizeSbomOverrides(settings.sbomOverrides),
  triageFilter: normalizeTriageFilterMode(settings.triageFilter),
  sbomPath: '',
  cacheStorage: normalizeCacheStorage(settings.cacheStorage),
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
    },
    cacheStorage: normalizeCacheStorage(settings.cacheStorage)
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

interface PersistentCacheServices {
  cacheDb: VulnCacheDb;
  cacheHydrator: CacheHydrator;
  cachePruner: CachePruner;
  cacheRepository: VulnCacheRepository;
  metadataRepository: SyncMetadataRepository;
  triageRepository: IndexedDbTriageRepository;
}

type LoadedPluginData = LegacyPersistedPluginData & Partial<VulnDashSettings> & {
  sboms?: LegacyImportedSbomConfig[];
};

interface VisibleTriageState {
  readonly correlationKey: string;
  readonly record: TriageRecord | null;
  readonly state: TriageState;
}

export default class VulnDashPlugin extends Plugin {
  private settings: VulnDashSettings = DEFAULT_SETTINGS;
  private stopPolling: (() => void) | null = null;
  private pollingEnabled = false;
  private readonly alertEngine = new AlertEngine();
  private readonly componentBacklinkService = new ComponentBacklinkService();
  private readonly componentInventoryService = new ComponentInventoryService();
  private readonly componentPreferenceService = componentPreferenceService;
  private readonly componentVulnerabilityLinkService = new ComponentVulnerabilityLinkService();
  private readonly relationshipNormalizer = new RelationshipNormalizer();
  private readonly sbomCatalogService = new SbomCatalogService();
  private readonly sbomComparisonService = new SbomComparisonService();
  private readonly sbomFilterMergeService = new SbomFilterMergeService();
  private sbomImportService: SbomImportService | null = null;
  private triageJoinUseCase: JoinTriageState | null = null;
  private triageSetUseCase: SetTriageState | null = null;
  private syncService: VulnerabilitySyncService | null = null;
  private syncServiceGeneration = 0;
  private dataProcessingChain: Promise<void> = Promise.resolve();
  private persistentCacheServices: PersistentCacheServices | null = null;
  private loadedPluginData: LoadedPluginData | null = null;
  private readonly storageScheduler = new CooperativeScheduler();
  private lastFetchAt = 0;
  private cachedVulnerabilities: Vulnerability[] = [];
  private visibleVulnerabilities: Vulnerability[] = [];
  private previousVisibleIds = new Set<string>();

  public override async onload(): Promise<void> {
    await this.loadSettings();
    await this.initializePersistentCache();
    await this.recomputeFilters();
    this.registerMarkdownNotePathObservers();

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
          getTriageFilter: () => this.settings.triageFilter,
          loadComponentInventory: async () => this.getComponentInventoryWorkspaceSnapshot(),
          onTriageFilterChange: async (triageFilter) => this.updateLocalSettings({ ...this.settings, triageFilter }),
          onTriageStateChange: async (vulnerability, state) => this.updateVulnerabilityTriage(vulnerability, state),
          openNotePath: async (notePath) => this.openNotePath(notePath),
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
    if (this.persistentCacheServices) {
      void this.persistentCacheServices.cacheDb.close();
    }
  }

  public async refreshNow(): Promise<void> {
    await this.runSync();
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

  public async getComponentInventoryWorkspaceSnapshot(): Promise<ComponentInventoryWorkspaceSnapshot> {
    const loadResults = await this.getSbomImportService().loadAllSboms(this.settings);
    const inventory = this.componentInventoryService.buildSnapshot(this.settings, loadResults);

    return {
      inventory,
      relationships: this.componentVulnerabilityLinkService.buildGraph(
        inventory.catalog.components,
        this.visibleVulnerabilities
      )
    };
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

  private processData(
    vulnerabilities: Vulnerability[],
    changedIds: ChangedVulnerabilityIds = createEmptyChangedVulnerabilityIds(),
    options: {
      suppressNotifications?: boolean;
    } = {}
  ): Promise<void> {
    this.dataProcessingChain = this.dataProcessingChain
      .catch(() => undefined)
      .then(async () => this.processDataInternal(vulnerabilities, changedIds, options));

    return this.dataProcessingChain;
  }

  private async processDataInternal(
    vulnerabilities: Vulnerability[],
    changedIds: ChangedVulnerabilityIds,
    options: {
      suppressNotifications?: boolean;
    }
  ): Promise<void> {
    const triageByKey = await this.loadVisibleTriageState(vulnerabilities);
    const filtered = this.alertEngine.filter(vulnerabilities, this.settings, {
      getTriageState: (vulnerability) => triageByKey.get(this.getVulnerabilityCacheKey(vulnerability))?.state
    });
    const filteredTriageByKey = new Map(filtered.map((vulnerability) => {
      const key = this.getVulnerabilityCacheKey(vulnerability);
      return [key, triageByKey.get(key) ?? this.createDefaultTriageState(vulnerability)] as const;
    }));
    const diagnostics = buildVisibilityDiagnostics(vulnerabilities, filtered);
    console.info('[vulndash.filter.visibility]', diagnostics);

    const currentVisible = new Map(filtered.map((vulnerability) => [this.getVulnerabilityCacheKey(vulnerability), vulnerability] as const));
    const candidateKeys = changedIds.added.length > 0 || changedIds.updated.length > 0 || changedIds.removed.length > 0
      ? Array.from(new Set([...changedIds.added, ...changedIds.updated])).sort((left, right) => left.localeCompare(right))
      : null;
    const newItems = candidateKeys
      ? candidateKeys
        .filter((key) => !this.previousVisibleIds.has(key))
        .map((key) => currentVisible.get(key))
        .filter((vulnerability): vulnerability is Vulnerability => Boolean(vulnerability))
      : filtered.filter((vulnerability) => !this.previousVisibleIds.has(this.getVulnerabilityCacheKey(vulnerability)));

    this.previousVisibleIds = new Set(currentVisible.keys());
    this.visibleVulnerabilities = filtered;
    this.updateView(filtered, filteredTriageByKey, {
      added: newItems.map((vulnerability) => this.getVulnerabilityCacheKey(vulnerability)),
      removed: changedIds.removed,
      updated: [...changedIds.updated].filter((key) => currentVisible.has(key))
    });

    if (options.suppressNotifications || newItems.length === 0) {
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

  private createDefaultTriageState(vulnerability: Pick<Vulnerability, 'id' | 'metadata' | 'source'>): VisibleTriageState {
    return {
      correlationKey: buildTriageCorrelationKeyForVulnerability(vulnerability),
      record: null,
      state: DEFAULT_TRIAGE_STATE
    };
  }

  private async loadVisibleTriageState(vulnerabilities: readonly Vulnerability[]): Promise<Map<string, VisibleTriageState>> {
    if (!this.triageJoinUseCase || vulnerabilities.length === 0) {
      return new Map(vulnerabilities.map((vulnerability) => [
        this.getVulnerabilityCacheKey(vulnerability),
        this.createDefaultTriageState(vulnerability)
      ] as const));
    }

    const joined = await this.triageJoinUseCase.execute(vulnerabilities);
    return new Map(joined.map((entry: JoinedTriageVulnerability) => [
      entry.cacheKey,
      {
        correlationKey: entry.correlationKey,
        record: entry.triageRecord,
        state: entry.triageState
      }
    ] as const));
  }

  private async updateVulnerabilityTriage(vulnerability: Vulnerability, state: TriageState): Promise<void> {
    if (!this.triageSetUseCase) {
      new Notice('Triage persistence is unavailable in this runtime.');
      return;
    }

    await this.triageSetUseCase.execute({
      state,
      updatedBy: 'local-user',
      vulnerability
    });
    await this.processData(this.cachedVulnerabilities, {
      added: [],
      removed: [],
      updated: [this.getVulnerabilityCacheKey(vulnerability)]
    }, {
      suppressNotifications: true
    });
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
    const workspaceSnapshot = await this.getComponentInventoryWorkspaceSnapshot();

    for (const vulnerability of vulnerabilities) {
      const notePath = this.getVulnerabilityNotePath(vulnerability);
      const exists = await this.app.vault.adapter.exists(notePath);
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
      const noteRelationships = this.componentBacklinkService.buildVulnerabilityNoteContext(
        vulnerabilityRef,
        workspaceSnapshot.relationships
      );

      if (!exists) {
        await this.app.vault.create(notePath, buildVulnerabilityNoteBody(vulnerability, noteRelationships));
      }

      await this.syncComponentNoteBacklinks(notePath, vulnerability, noteRelationships.relatedComponentNotePaths);
    }
  }

  private getVulnerabilityNotePath(vulnerability: Vulnerability): string {
    const safeId = vulnerability.id.replace(/[^A-Za-z0-9._-]/g, '-');
    return normalizePath(`${this.settings.autoNoteFolder}/${safeId}.md`);
  }

  private async syncComponentNoteBacklinks(
    vulnerabilityNotePath: string,
    vulnerability: Vulnerability,
    componentNotePaths: readonly string[]
  ): Promise<void> {
    for (const componentNotePath of componentNotePaths) {
      const normalizedPath = normalizePath(componentNotePath);
      const exists = await this.app.vault.adapter.exists(normalizedPath);
      if (!exists) {
        continue;
      }

      const currentContent = await this.app.vault.adapter.read(normalizedPath);
      const nextContent = this.componentBacklinkService.upsertRelatedVulnerabilitySection(currentContent, [{
        label: vulnerability.id,
        notePath: vulnerabilityNotePath
      }]);

      if (nextContent !== currentContent) {
        await this.app.vault.adapter.write(normalizedPath, nextContent);
      }
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

    this.pollingEnabled = true;
    let timeoutHandle: number | null = null;

    const execute = async (): Promise<void> => {
      if (!this.pollingEnabled) {
        return;
      }

      await this.runSync({ bypassCache: true, showFailureNotice: false });
      if (!this.pollingEnabled) {
        return;
      }

      timeoutHandle = window.setTimeout(() => {
        void execute();
      }, this.settings.pollingIntervalMs);
    };

    this.stopPolling = () => {
      this.pollingEnabled = false;
      if (timeoutHandle !== null) {
        window.clearTimeout(timeoutHandle);
        timeoutHandle = null;
      }
    };

    void execute();
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

  private async runSync(options: {
    bypassCache?: boolean;
    showFailureNotice?: boolean;
  } = {}): Promise<void> {
    const now = Date.now();
    const cacheValid = now - this.lastFetchAt <= this.settings.cacheDurationMs;
    if (!options.bypassCache && cacheValid && this.cachedVulnerabilities.length > 0) {
      await this.processData(this.cachedVulnerabilities);
      return;
    }

    const syncService = this.getOrCreateSyncService();
    const syncServiceGeneration = this.syncServiceGeneration;

    try {
      const outcome = await syncService.syncNow();
      if (this.syncService !== syncService || this.syncServiceGeneration !== syncServiceGeneration) {
        return;
      }

      await this.applySyncOutcome(outcome, options.showFailureNotice ?? true);
    } catch {
      if (options.showFailureNotice ?? true) {
        new Notice('VulnDash refresh failed. Check your network or API tokens.');
      }
    }
  }

  private async applySyncOutcome(outcome: SyncOutcome, showFailureNotice: boolean): Promise<void> {
    const syncSummaries = summarizeSyncResults(outcome.results);
    for (const summary of syncSummaries) {
      console.info('[vulndash.sync.feed_summary]', summary);
    }

    const failureNotice = buildFailureNoticeMessage(outcome.results);
    if (showFailureNotice && failureNotice) {
      new Notice(failureNotice);
    }

    this.cachedVulnerabilities = outcome.vulnerabilities;
    this.settings.sourceSyncCursor = this.persistentCacheServices ? {} : outcome.sourceSyncCursor;
    await this.saveSettings();
    this.lastFetchAt = Date.now();
    this.persistentCacheServices?.cachePruner.schedule(this.settings.cacheStorage);
    await this.processData(outcome.vulnerabilities, createEmptyChangedVulnerabilityIds(), { suppressNotifications: true });
  }

  private getOrCreateSyncService(): VulnerabilitySyncService {
    if (this.syncService) {
      return this.syncService;
    }

    const client = new HttpClient();
    const feeds = buildFeedsFromConfig(this.settings.feeds, client, this.settings.syncControls);
    const generation = this.syncServiceGeneration;
    const syncService = new VulnerabilitySyncService({
      controls: this.settings.syncControls,
      feeds,
      ...(this.persistentCacheServices ? {
        persistence: {
          cacheHydrationLimit: this.settings.cacheStorage.hydrateMaxItems,
          cacheHydrationPageSize: this.settings.cacheStorage.hydratePageSize,
          cacheStore: this.persistentCacheServices.cacheRepository,
          metadataStore: this.persistentCacheServices.metadataRepository
        }
      } : {}),
      onPipelineEvent: (event) => {
        if (this.syncService !== syncService || this.syncServiceGeneration !== generation) {
          return;
        }

        this.handlePipelineEvent(event);
      },
      state: {
        cache: this.cachedVulnerabilities,
        sourceSyncCursor: this.settings.sourceSyncCursor
      }
    });

    this.syncService = syncService;
    return syncService;
  }

  private invalidateSyncService(): void {
    this.syncServiceGeneration += 1;
    this.syncService = null;
  }

  private handlePipelineEvent(event: PipelineEvent): void {
    if (event.stage !== 'notify') {
      return;
    }

    void this.processData([...event.vulnerabilities], event.changedIds);
  }

  private getVulnerabilityCacheKey(vulnerability: Vulnerability): string {
    return buildVulnerabilityCacheKey(vulnerability);
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

  private updateView(
    vulnerabilities: Vulnerability[],
    triageByKey: ReadonlyMap<string, VisibleTriageState>,
    changedIds: ChangedVulnerabilityIds = createEmptyChangedVulnerabilityIds()
  ): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setData(vulnerabilities, triageByKey, changedIds);
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

  private async openNotePath(notePath: string): Promise<void> {
    const normalized = normalizePath(notePath);
    const target = this.app.vault.getAbstractFileByPath(normalized);

    if (!(target instanceof TFile)) {
      new Notice(`Note not found: ${normalized}`);
      return;
    }

    const leaf = this.app.workspace.getLeaf(true);
    await leaf.openFile(target);
    this.app.workspace.revealLeaf(leaf);
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

  private async initializePersistentCache(): Promise<void> {
    try {
      const cacheDb = new VulnCacheDb();
      await cacheDb.open();
      const cacheRepository = new VulnCacheRepository(cacheDb);
      const metadataRepository = new SyncMetadataRepository(cacheDb);
      const triageRepository = new IndexedDbTriageRepository(cacheDb);
      const cacheHydrator = new CacheHydrator(cacheRepository, this.storageScheduler);
      const cachePruner = new CachePruner(cacheRepository, this.storageScheduler);
      this.persistentCacheServices = {
        cacheDb,
        cacheHydrator,
        cachePruner,
        cacheRepository,
        metadataRepository,
        triageRepository
      };
      this.triageJoinUseCase = new JoinTriageState(triageRepository);
      this.triageSetUseCase = new SetTriageState(triageRepository);

      const migration = await new LegacyDataMigration(cacheRepository, metadataRepository).migrate(
        this.loadedPluginData,
        this.settings.feeds
      );

      const hydrated = await cacheHydrator.hydrateLatest({
        limit: this.settings.cacheStorage.hydrateMaxItems,
        pageSize: this.settings.cacheStorage.hydratePageSize
      });
      if (hydrated.length > 0) {
        this.cachedVulnerabilities = hydrated;
        this.lastFetchAt = Date.now();
      }

      cachePruner.schedule(this.settings.cacheStorage);

      if (migration.removedLegacyFields) {
        this.settings = normalizeRuntimeSettings({
          ...this.settings,
          sourceSyncCursor: {}
        });
        await this.saveSettings();
      }
    } catch (error) {
      this.persistentCacheServices = null;
      console.warn('[vulndash.cache.persistence_unavailable]', error);
    }
  }
  private async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    const loadedSettings = (loaded as LoadedPluginData | null) ?? null;
    this.loadedPluginData = loadedSettings;
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
    this.invalidateSyncService();

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

    const dataToSave = buildPersistedSettingsSnapshot({
      ...this.settings,
      sourceSyncCursor: this.persistentCacheServices ? {} : this.settings.sourceSyncCursor
    }, {
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
    this.invalidateSyncService();
    await this.saveSettings();
    this.persistentCacheServices?.cachePruner.schedule(this.settings.cacheStorage);

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
      this.sbomImportService = new SbomImportService(
        this.app.vault.adapter,
        undefined,
        new ComponentNoteResolverFactory(this.app.vault, this.app.metadataCache)
      );
    }
    return this.sbomImportService;
  }

  private registerMarkdownNotePathObservers(): void {
    const invalidateComponentNotePaths = (): void => {
      this.getSbomImportService().invalidateAllCaches();
      this.updateViewSettings();
    };

    const shouldInvalidateForFile = (file: TFile): boolean =>
      file.extension.toLowerCase() === 'md';
    const shouldInvalidateForAbstractFile = (file: TAbstractFile): boolean =>
      file instanceof TFile && shouldInvalidateForFile(file);

    this.registerEvent(this.app.vault.on('create', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
    this.registerEvent(this.app.vault.on('modify', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
    this.registerEvent(this.app.vault.on('delete', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
    this.registerEvent(this.app.vault.on('rename', (file) => {
      if (shouldInvalidateForAbstractFile(file)) {
        invalidateComponentNotePaths();
      }
    }));
  }
}














