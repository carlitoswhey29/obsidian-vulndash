import { BUILT_IN_FEEDS, FEED_TYPES } from '../../domain/feeds/FeedTypes';
import type { TriageState } from '../../domain/triage/TriageState';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import type { LegacyPersistedPluginData } from '../../infrastructure/storage/LegacyDataMigration';
import { ComponentPreferenceService } from '../sbom/ComponentPreferenceService';
import { normalizeTriageFilterMode } from '../triage/FilterByTriageState';
import {
  DEFAULT_CACHE_STORAGE,
  DEFAULT_COLUMN_VISIBILITY,
  DEFAULT_DAILY_ROLLUP_SETTINGS,
  DEFAULT_FEEDS,
  DEFAULT_SETTINGS,
  MAX_OSV_CONCURRENT_BATCHES,
  SETTINGS_VERSION,
  getDefaultOsvFeedConfig,
  normalizeOsvEndpointUrl,
  normalizeOsvMaxBatchSize
} from '../use-cases/DefaultSettings';
import type {
  CacheStorageSettings,
  DailyRollupSettings,
  FeedConfig,
  ImportedSbomConfig,
  SbomComponentOverride,
  VulnDashSettings
} from '../use-cases/types';
import { buildSbomOverrideKey } from '../use-cases/types';

export interface LegacyImportedSbomComponent {
  bomRef?: unknown;
  cpe?: unknown;
  excluded?: unknown;
  name?: unknown;
  normalizedName?: unknown;
  purl?: unknown;
}

export interface LegacyImportedSbomConfig extends Partial<ImportedSbomConfig> {
  components?: LegacyImportedSbomComponent[];
  lastImportError?: unknown;
  lastImportHash?: unknown;
}

export type SettingsMigrationInput = LegacyPersistedPluginData & Partial<VulnDashSettings> & {
  autoHighNoteCreationEnabled?: unknown;
  autoNoteCreationEnabled?: unknown;
  autoNoteFolder?: unknown;
  sboms?: LegacyImportedSbomConfig[];
};

interface SettingsMigrationStep {
  readonly name: string;
  readonly toVersion: number;
  migrate(settings: SettingsMigrationInput): SettingsMigrationInput;
  shouldApply(settings: SettingsMigrationInput): boolean;
}

export interface SettingsMigrationResult {
  readonly appliedSteps: readonly string[];
  readonly didMigrate: boolean;
  readonly fromVersion: number;
  readonly settings: VulnDashSettings;
  readonly toVersion: number;
}

const componentPreferenceService = new ComponentPreferenceService();
const legacyNameNormalizer = new ProductNameNormalizer();

const normalizeStoredPath = (value: string): string =>
  value
    .replace(/\\/g, '/')
    .split('/')
    .filter((segment) => segment.length > 0)
    .join('/');

const cloneFeedConfig = (feed: FeedConfig): FeedConfig => ({ ...feed });

const normalizePositiveInteger = (value: unknown, fallback: number): number =>
  typeof value === 'number' && Number.isFinite(value) && value > 0
    ? Math.floor(value)
    : fallback;

const normalizeBoundedPositiveInteger = (value: unknown, fallback: number, maximum: number): number =>
  Math.min(normalizePositiveInteger(value, fallback), maximum);

const normalizeFeedConfigs = (feeds: FeedConfig[] | undefined): FeedConfig[] => (feeds ?? []).map((feed) => {
  if (feed.type === FEED_TYPES.NVD) {
    return {
      ...feed,
      dateFilterType: feed.dateFilterType === 'published' ? 'published' : 'modified'
    };
  }

  if (feed.type === FEED_TYPES.OSV) {
    const defaults = getDefaultOsvFeedConfig();
    return {
      ...feed,
      cacheTtlMs: normalizePositiveInteger(feed.cacheTtlMs, defaults.cacheTtlMs),
      negativeCacheTtlMs: normalizePositiveInteger(feed.negativeCacheTtlMs, defaults.negativeCacheTtlMs),
      requestTimeoutMs: normalizePositiveInteger(feed.requestTimeoutMs, defaults.requestTimeoutMs),
      maxConcurrentBatches: normalizeBoundedPositiveInteger(
        feed.maxConcurrentBatches,
        defaults.maxConcurrentBatches,
        MAX_OSV_CONCURRENT_BATCHES
      ),
      osvEndpointUrl: normalizeOsvEndpointUrl(feed.osvEndpointUrl, defaults.osvEndpointUrl),
      osvMaxBatchSize: normalizeOsvMaxBatchSize(feed.osvMaxBatchSize, defaults.osvMaxBatchSize)
    };
  }

  return { ...feed };
});

const normalizeStringList = (values: string[] | undefined): string[] => {
  if (!Array.isArray(values)) {
    return [];
  }

  return Array.from(new Set(values
    .map((value) => typeof value === 'string' ? value.trim() : '')
    .filter((value) => value.length > 0)));
};

const normalizePathList = (values: string[] | undefined): string[] => {
  if (!Array.isArray(values)) {
    return [];
  }

  return Array.from(new Set(values
    .map((value) => typeof value === 'string' ? normalizeStoredPath(value.trim()) : '')
    .filter((value) => value.length > 0)));
};

const buildLegacySbomLabel = (path: string): string => {
  const normalized = normalizeStoredPath(path);
  const segments = normalized.split('/').filter(Boolean);
  const candidate = segments.at(-1);
  return candidate && candidate.length > 0 ? candidate : 'SBOM';
};

const getTrimmedString = (value: unknown): string => typeof value === 'string' ? value.trim() : '';

export const normalizeImportedSbomConfig = (
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
  const linkedProjectNotePath = getTrimmedString(sbom.linkedProjectNotePath);
  const linkedProjectDisplayName = getTrimmedString(sbom.linkedProjectDisplayName);

  const normalized: ImportedSbomConfig = {
    contentHash,
    enabled: sbom.enabled ?? true,
    id: getTrimmedString(sbom.id) || `sbom-${index + 1}`,
    label: getTrimmedString(sbom.label) || buildLegacySbomLabel(getTrimmedString(sbom.path)),
    lastImportedAt,
    path: getTrimmedString(sbom.path) ? normalizeStoredPath(getTrimmedString(sbom.path)) : ''
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
  if (linkedProjectNotePath) {
    normalized.linkedProjectNotePath = normalizeStoredPath(linkedProjectNotePath);
  }
  if (linkedProjectDisplayName) {
    normalized.linkedProjectDisplayName = linkedProjectDisplayName;
  }

  return normalized;
};

const createLegacySbomConfig = (path: string): ImportedSbomConfig => {
  const normalizedPath = normalizeStoredPath(path);
  return {
    contentHash: '',
    enabled: true,
    id: 'sbom-1',
    label: buildLegacySbomLabel(normalizedPath),
    lastImportedAt: 0,
    path: normalizedPath
  };
};

export const normalizeSbomOverride = (override: Partial<SbomComponentOverride>): SbomComponentOverride | null => {
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

const migrateLegacySbomOverrides = (sboms: readonly LegacyImportedSbomConfig[]): Record<string, SbomComponentOverride> => {
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

const normalizeDailyRollupSettings = (
  value: Partial<DailyRollupSettings> | undefined,
  legacy: {
    autoHighNoteCreationEnabled?: unknown;
    autoNoteCreationEnabled?: unknown;
    autoNoteFolder?: unknown;
  } = {}
): DailyRollupSettings => {
  const severityThreshold = value?.severityThreshold ?? (legacy.autoHighNoteCreationEnabled === true ? 'HIGH' : DEFAULT_DAILY_ROLLUP_SETTINGS.severityThreshold);
  const excludedTriageStates = Array.isArray(value?.excludedTriageStates)
    ? Array.from(new Set(value.excludedTriageStates.filter((state): state is TriageState => typeof state === 'string' && state.length > 0)))
    : [...DEFAULT_DAILY_ROLLUP_SETTINGS.excludedTriageStates];
  const folderPath = typeof value?.folderPath === 'string' && value.folderPath.trim().length > 0
    ? normalizeStoredPath(value.folderPath.trim())
    : (typeof legacy.autoNoteFolder === 'string' && legacy.autoNoteFolder.trim().length > 0
      ? normalizeStoredPath(legacy.autoNoteFolder.trim())
      : DEFAULT_DAILY_ROLLUP_SETTINGS.folderPath);

  return {
    autoGenerateOnFirstSyncOfDay: typeof value?.autoGenerateOnFirstSyncOfDay === 'boolean'
      ? value.autoGenerateOnFirstSyncOfDay
      : legacy.autoNoteCreationEnabled === true || legacy.autoHighNoteCreationEnabled === true,
    excludedTriageStates,
    folderPath,
    includeUnmappedFindings: value?.includeUnmappedFindings ?? DEFAULT_DAILY_ROLLUP_SETTINGS.includeUnmappedFindings,
    lastAutoGeneratedOn: typeof value?.lastAutoGeneratedOn === 'string' ? value.lastAutoGeneratedOn.trim() : '',
    severityThreshold
  };
};

const hasLegacyCursorKeys = (cursor: Record<string, string> | undefined): boolean =>
  Boolean(
    (BUILT_IN_FEEDS.NVD.legacyCursorKey && cursor?.[BUILT_IN_FEEDS.NVD.legacyCursorKey])
    || (BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey && cursor?.[BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey])
  );

const migrateLegacySourceSyncCursor = (cursor: Record<string, string> | undefined): Record<string, string> => {
  const normalized = { ...(cursor ?? {}) };
  const legacyNvdCursor = BUILT_IN_FEEDS.NVD.legacyCursorKey ? normalized[BUILT_IN_FEEDS.NVD.legacyCursorKey] : undefined;
  const legacyGithubCursor = BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey
    ? normalized[BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey]
    : undefined;

  if (legacyNvdCursor && !normalized[BUILT_IN_FEEDS.NVD.id]) {
    normalized[BUILT_IN_FEEDS.NVD.id] = legacyNvdCursor;
  }
  if (legacyGithubCursor && !normalized[BUILT_IN_FEEDS.GITHUB_ADVISORY.id]) {
    normalized[BUILT_IN_FEEDS.GITHUB_ADVISORY.id] = legacyGithubCursor;
  }
  if (BUILT_IN_FEEDS.NVD.legacyCursorKey) {
    delete normalized[BUILT_IN_FEEDS.NVD.legacyCursorKey];
  }
  if (BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey) {
    delete normalized[BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey];
  }

  return normalized;
};

const migrateLegacyFeeds = (settings: SettingsMigrationInput): FeedConfig[] => {
  const hasDynamicFeeds = Array.isArray(settings.feeds) && settings.feeds.length > 0;
  const feeds = hasDynamicFeeds
    ? normalizeFeedConfigs(settings.feeds)
    : DEFAULT_FEEDS.map((feed) => cloneFeedConfig(feed));

  if (!hasDynamicFeeds) {
    const nvdFeed = feeds.find((feed): feed is Extract<FeedConfig, { type: typeof FEED_TYPES.NVD }> =>
      feed.type === FEED_TYPES.NVD && feed.id === BUILT_IN_FEEDS.NVD.id);
    if (nvdFeed && settings.nvdApiKey) {
      nvdFeed.apiKey = settings.nvdApiKey;
    }
    if (typeof settings.enableNvdFeed === 'boolean' && nvdFeed) {
      nvdFeed.enabled = settings.enableNvdFeed;
    }

    const githubFeed = feeds.find((feed) =>
      feed.type === FEED_TYPES.GITHUB_ADVISORY && feed.id === BUILT_IN_FEEDS.GITHUB_ADVISORY.id);
    if (githubFeed && settings.githubToken) {
      githubFeed.token = settings.githubToken;
    }
    if (typeof settings.enableGithubFeed === 'boolean' && githubFeed) {
      githubFeed.enabled = settings.enableGithubFeed;
    }
  }

  return feeds;
};

const migrateLegacyProductFilters = (settings: SettingsMigrationInput): Pick<VulnDashSettings, 'manualProductFilters' | 'productFilters'> => {
  const legacyProductFilters = normalizeStringList(settings.productFilters);
  const manualProductFilters = normalizeStringList(settings.manualProductFilters ?? legacyProductFilters);

  return {
    manualProductFilters,
    productFilters: normalizeStringList(manualProductFilters)
  };
};

const migrateLegacySbomSettings = (
  settings: SettingsMigrationInput
): Pick<VulnDashSettings, 'sbomOverrides' | 'sbomPath' | 'sboms'> => {
  const rawSboms = Array.isArray(settings.sboms) ? settings.sboms : [];
  const sboms = rawSboms.length > 0
    ? rawSboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index))
    : (settings.sbomPath?.trim()
      ? [createLegacySbomConfig(settings.sbomPath)]
      : []);
  const migratedOverrides = migrateLegacySbomOverrides(rawSboms);

  return {
    sboms,
    sbomOverrides: normalizeSbomOverrides({
      ...migratedOverrides,
      ...(settings.sbomOverrides ?? {})
    }),
    sbomPath: ''
  };
};

const normalizeRuntimeSettingsInternal = (settings: VulnDashSettings): VulnDashSettings => ({
  ...componentPreferenceService.normalizeSettings(settings),
  keywordFilters: normalizeStringList(settings.keywordFilters),
  manualProductFilters: normalizeStringList(settings.manualProductFilters),
  productFilters: normalizeStringList(settings.productFilters),
  feeds: normalizeFeedConfigs(settings.feeds),
  sbomFolders: normalizePathList(settings.sbomFolders),
  sboms: settings.sboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index)),
  sbomOverrides: normalizeSbomOverrides(settings.sbomOverrides),
  dashboardDateField: settings.dashboardDateField === 'published' ? 'published' : 'modified',
  triageFilter: normalizeTriageFilterMode(settings.triageFilter),
  dailyRollup: normalizeDailyRollupSettings(settings.dailyRollup),
  sbomPath: '',
  cacheStorage: normalizeCacheStorage(settings.cacheStorage),
  settingsVersion: SETTINGS_VERSION
});

const buildNormalizedSettings = (settings: SettingsMigrationInput): VulnDashSettings => {
  const migratedSbomSettings = migrateLegacySbomSettings(settings);
  const defaultedFeeds = migrateLegacyFeeds(settings);

  return normalizeRuntimeSettingsInternal({
    ...DEFAULT_SETTINGS,
    ...settings,
    dailyRollup: normalizeDailyRollupSettings(settings.dailyRollup, settings),
    feeds: defaultedFeeds,
    sourceSyncCursor: migrateLegacySourceSyncCursor(settings.sourceSyncCursor),
    sboms: migratedSbomSettings.sboms,
    sbomOverrides: migratedSbomSettings.sbomOverrides,
    sbomPath: migratedSbomSettings.sbomPath,
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

const defaultMigrationSteps: readonly SettingsMigrationStep[] = [
  {
    name: 'legacy-feed-config',
    toVersion: 5,
    shouldApply: (settings) =>
      (settings.settingsVersion ?? 0) < 5
      || !Array.isArray(settings.feeds)
      || settings.feeds.length === 0,
    migrate: (settings) => ({
      ...settings,
      feeds: migrateLegacyFeeds(settings)
    })
  },
  {
    name: 'legacy-source-sync-cursors',
    toVersion: 6,
    shouldApply: (settings) =>
      (settings.settingsVersion ?? 0) < 6
      || hasLegacyCursorKeys(settings.sourceSyncCursor),
    migrate: (settings) => ({
      ...settings,
      sourceSyncCursor: migrateLegacySourceSyncCursor(settings.sourceSyncCursor)
    })
  },
  {
    name: 'legacy-product-filters',
    toVersion: 7,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 7,
    migrate: (settings) => ({
      ...settings,
      ...migrateLegacyProductFilters(settings)
    })
  },
  {
    name: 'legacy-daily-rollup',
    toVersion: 8,
    shouldApply: (settings) =>
      (settings.settingsVersion ?? 0) < 8
      || settings.autoHighNoteCreationEnabled === true
      || settings.autoNoteCreationEnabled === true
      || (typeof settings.autoNoteFolder === 'string' && settings.autoNoteFolder.trim().length > 0),
    migrate: (settings) => ({
      ...settings,
      dailyRollup: normalizeDailyRollupSettings(settings.dailyRollup, settings)
    })
  },
  {
    name: 'legacy-sbom-settings',
    toVersion: 9,
    shouldApply: (settings) =>
      (settings.settingsVersion ?? 0) < 9
      || Boolean(settings.sbomPath?.trim()),
    migrate: (settings) => ({
      ...settings,
      ...migrateLegacySbomSettings(settings)
    })
  },
  {
    name: 'osv-operational-config',
    toVersion: 10,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 10,
    migrate: (settings) => ({
      ...settings,
      feeds: normalizeFeedConfigs(settings.feeds)
    })
  }
];

export class SettingsMigrator {
  public constructor(
    private readonly steps: readonly SettingsMigrationStep[] = defaultMigrationSteps
  ) {}

  public migrate(settings: SettingsMigrationInput): SettingsMigrationResult {
    const fromVersion = settings.settingsVersion ?? 0;
    let current: SettingsMigrationInput = { ...settings };
    const appliedSteps: string[] = [];

    for (const step of this.steps) {
      if (!step.shouldApply(current)) {
        continue;
      }

      current = {
        ...step.migrate(current),
        settingsVersion: Math.max(current.settingsVersion ?? 0, step.toVersion)
      };
      appliedSteps.push(step.name);
    }

    return {
      appliedSteps,
      didMigrate: appliedSteps.length > 0 || fromVersion < SETTINGS_VERSION,
      fromVersion,
      settings: buildNormalizedSettings(current),
      toVersion: SETTINGS_VERSION
    };
  }

  public normalizeRuntimeSettings(settings: VulnDashSettings): VulnDashSettings {
    return normalizeRuntimeSettingsInternal(settings);
  }
}

const defaultSettingsMigrator = new SettingsMigrator();

export const normalizeRuntimeSettings = (settings: VulnDashSettings): VulnDashSettings =>
  defaultSettingsMigrator.normalizeRuntimeSettings(settings);

export const migrateLegacySettings = (settings: SettingsMigrationInput): VulnDashSettings =>
  defaultSettingsMigrator.migrate(settings).settings;

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
