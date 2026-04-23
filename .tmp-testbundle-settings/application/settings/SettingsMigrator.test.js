// tests/application/settings/SettingsMigrator.test.ts
import assert from "node:assert/strict";
import test from "node:test";

// src/domain/feeds/FeedTypes.ts
var FEED_TYPES = {
  GENERIC_JSON: "generic_json",
  GITHUB_ADVISORY: "github_advisory",
  GITHUB_REPO: "github_repo",
  NVD: "nvd",
  OSV: "osv"
};
var BUILT_IN_FEEDS = {
  GITHUB_ADVISORY: {
    id: "github-advisories-default",
    legacyCursorKey: "GitHub",
    legacySourceAliases: ["github"],
    name: "GitHub",
    type: FEED_TYPES.GITHUB_ADVISORY
  },
  NVD: {
    id: "nvd-default",
    legacyCursorKey: "NVD",
    legacySourceAliases: [FEED_TYPES.NVD],
    name: "NVD",
    type: FEED_TYPES.NVD
  },
  OSV: {
    id: "osv-default",
    legacySourceAliases: [FEED_TYPES.OSV],
    name: "OSV",
    type: FEED_TYPES.OSV
  }
};

// src/domain/services/ProductNameNormalizer.ts
var ProductNameNormalizer = class {
  normalize(rawName) {
    const trimmed = rawName.trim();
    if (!trimmed) {
      return "";
    }
    if (trimmed.startsWith("cpe:2.3:")) {
      return this.normalizeCpe(trimmed);
    }
    return this.normalizeGeneric(trimmed);
  }
  normalizeCpe(cpe) {
    const parts = cpe.split(":");
    const vendor = this.cleanCpeToken(parts[3] ?? "");
    const product = this.cleanCpeToken(parts[4] ?? "");
    const version = this.cleanCpeToken(parts[5] ?? "");
    const base = [vendor, product].filter(Boolean).join(" ");
    const namedBase = this.toDisplayName(base);
    if (!namedBase) {
      return this.normalizeGeneric(cpe);
    }
    if (!version || version === "*" || version === "-") {
      return namedBase;
    }
    return `${namedBase} ${version}`;
  }
  cleanCpeToken(token) {
    if (!token || token === "*" || token === "-") {
      return "";
    }
    return token.replace(/\\([\\:*?!])/g, "$1").replace(/_/g, " ").trim();
  }
  normalizeGeneric(value) {
    const collapsed = value.replace(/[@/]/g, " ").replace(/[_-]+/g, " ").replace(/\s+/g, " ").trim();
    return this.toDisplayName(collapsed);
  }
  toDisplayName(value) {
    return value.split(" ").filter(Boolean).map((part) => {
      if (/^\d+(\.\d+)*$/.test(part)) {
        return part;
      }
      return part.charAt(0).toUpperCase() + part.slice(1);
    }).join(" ");
  }
};

// src/application/sbom/ComponentPreferenceService.ts
var compareKeys = (left, right) => left.localeCompare(right);
var normalizeComponentKey = (key) => key.trim().toLowerCase();
var normalizeStoredKeys = (values) => {
  if (!Array.isArray(values)) {
    return [];
  }
  const normalized = /* @__PURE__ */ new Set();
  for (const value of values) {
    if (typeof value !== "string") {
      continue;
    }
    const normalizedValue = normalizeComponentKey(value);
    if (normalizedValue) {
      normalized.add(normalizedValue);
    }
  }
  return Array.from(normalized).sort(compareKeys);
};
var createPreferenceState = (settings) => ({
  disabledKeys: new Set(normalizeStoredKeys(settings.disabledSbomComponentKeys)),
  followedKeys: new Set(normalizeStoredKeys(settings.followedSbomComponentKeys))
});
var createTrackedComponentWithPreferences = (component, state) => {
  const normalizedKey = normalizeComponentKey(component.key);
  return {
    ...component,
    isEnabled: !state.disabledKeys.has(normalizedKey),
    isFollowed: state.followedKeys.has(normalizedKey)
  };
};
var ComponentPreferenceService = class {
  normalizeSettings(settings) {
    return {
      ...settings,
      disabledSbomComponentKeys: normalizeStoredKeys(settings.disabledSbomComponentKeys),
      followedSbomComponentKeys: normalizeStoredKeys(settings.followedSbomComponentKeys)
    };
  }
  isFollowed(key, settings) {
    const normalizedKey = normalizeComponentKey(key);
    if (!normalizedKey) {
      return false;
    }
    return createPreferenceState(settings).followedKeys.has(normalizedKey);
  }
  isEnabled(key, settings) {
    const normalizedKey = normalizeComponentKey(key);
    if (!normalizedKey) {
      return true;
    }
    return !createPreferenceState(settings).disabledKeys.has(normalizedKey);
  }
  follow(key, settings) {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.followedKeys.add(normalizedKey);
    }, key);
  }
  unfollow(key, settings) {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.followedKeys.delete(normalizedKey);
    }, key);
  }
  disable(key, settings) {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.disabledKeys.add(normalizedKey);
    }, key);
  }
  enable(key, settings) {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.disabledKeys.delete(normalizedKey);
    }, key);
  }
  applyPreferences(catalog, settings) {
    const state = createPreferenceState(settings);
    return {
      ...catalog,
      components: catalog.components.map((component) => createTrackedComponentWithPreferences(component, state))
    };
  }
  updateSettings(settings, update, key) {
    const state = createPreferenceState(settings);
    const normalizedKey = normalizeComponentKey(key);
    if (normalizedKey) {
      update(state, normalizedKey);
    }
    return {
      ...settings,
      disabledSbomComponentKeys: Array.from(state.disabledKeys).sort(compareKeys),
      followedSbomComponentKeys: Array.from(state.followedKeys).sort(compareKeys)
    };
  }
};

// src/domain/triage/TriageState.ts
var TRIAGE_STATES = [
  "active",
  "investigating",
  "accepted_risk",
  "mitigated",
  "false_positive",
  "suppressed"
];
var DEFAULT_TRIAGE_STATE = "active";
var CLOSED_TRIAGE_STATES = ["mitigated", "false_positive", "suppressed"];
var TRIAGE_STATE_SET = new Set(TRIAGE_STATES);
var normalizeStateValue = (value) => value.trim().toLowerCase().replace(/[\s-]+/g, "_");
var isTriageState = (value) => typeof value === "string" && TRIAGE_STATE_SET.has(normalizeStateValue(value));
var parseTriageState = (value, fallback = DEFAULT_TRIAGE_STATE) => {
  if (typeof value !== "string") {
    return fallback;
  }
  const normalized = normalizeStateValue(value);
  return TRIAGE_STATE_SET.has(normalized) ? normalized : fallback;
};

// src/application/triage/FilterByTriageState.ts
var normalizeTriageFilterMode = (value) => {
  if (value === "all" || value === "active-only" || value === "hide-mitigated") {
    return value;
  }
  if (isTriageState(value)) {
    return parseTriageState(value);
  }
  return "all";
};

// src/application/use-cases/DefaultSettings.ts
var DEFAULT_COLUMN_VISIBILITY = {
  id: true,
  title: true,
  source: true,
  severity: true,
  cvssScore: true,
  publishedAt: true
};
var DEFAULT_FEEDS = [
  {
    id: BUILT_IN_FEEDS.NVD.id,
    name: BUILT_IN_FEEDS.NVD.name,
    type: BUILT_IN_FEEDS.NVD.type,
    enabled: true,
    dateFilterType: "modified"
  },
  {
    id: BUILT_IN_FEEDS.GITHUB_ADVISORY.id,
    name: BUILT_IN_FEEDS.GITHUB_ADVISORY.name,
    type: BUILT_IN_FEEDS.GITHUB_ADVISORY.type,
    enabled: true
  },
  {
    id: BUILT_IN_FEEDS.OSV.id,
    name: BUILT_IN_FEEDS.OSV.name,
    type: BUILT_IN_FEEDS.OSV.type,
    enabled: false,
    cacheTtlMs: 6 * 60 * 60 * 1e3,
    negativeCacheTtlMs: 60 * 60 * 1e3,
    requestTimeoutMs: 15e3,
    maxConcurrentBatches: 4
  }
];
var MAX_OSV_CONCURRENT_BATCHES = 8;
var DEFAULT_CACHE_STORAGE = {
  hardCap: 5e3,
  hydrateMaxItems: 1e3,
  hydratePageSize: 200,
  pruneBatchSize: 250,
  ttlMs: 30 * 24 * 60 * 60 * 1e3
};
var DEFAULT_DAILY_ROLLUP_SETTINGS = {
  folderPath: "VulnDash Briefings",
  severityThreshold: "HIGH",
  excludedTriageStates: [...CLOSED_TRIAGE_STATES],
  includeUnmappedFindings: true,
  autoGenerateOnFirstSyncOfDay: false,
  lastAutoGeneratedOn: ""
};
var DEFAULT_SYNC_CONTROLS = {
  maxPages: 10,
  maxItems: 500,
  retryCount: 3,
  backoffBaseMs: 1e3,
  overlapWindowMs: 18e4,
  bootstrapLookbackMs: 864e5,
  debugHttpMetadata: false
};
var SETTINGS_VERSION = 9;
var DEFAULT_SETTINGS = {
  pollingIntervalMs: 6e4,
  pollOnStartup: true,
  keywordFilters: [],
  manualProductFilters: [],
  sbomFolders: [],
  followedSbomComponentKeys: [],
  disabledSbomComponentKeys: [],
  productFilters: [],
  minSeverity: "MEDIUM",
  minCvssScore: 4,
  nvdApiKey: "",
  githubToken: "",
  systemNotificationsEnabled: true,
  desktopAlertsHighOrCritical: false,
  cacheDurationMs: 6e4,
  maxResults: 200,
  defaultSortOrder: "publishedAt",
  dashboardDateField: "modified",
  colorCodedSeverity: true,
  columnVisibility: DEFAULT_COLUMN_VISIBILITY,
  triageFilter: "all",
  keywordRegexEnabled: false,
  enableNvdFeed: true,
  enableGithubFeed: true,
  dailyRollup: { ...DEFAULT_DAILY_ROLLUP_SETTINGS },
  sboms: [],
  sbomOverrides: {},
  sbomImportMode: "append",
  sbomPath: "",
  syncControls: { ...DEFAULT_SYNC_CONTROLS },
  sourceSyncCursor: {},
  cacheStorage: DEFAULT_CACHE_STORAGE,
  settingsVersion: SETTINGS_VERSION,
  feeds: DEFAULT_FEEDS.map((feed) => ({ ...feed }))
};
var getDefaultOsvFeedConfig = () => {
  const defaultFeed = DEFAULT_FEEDS.find((feed) => feed.type === FEED_TYPES.OSV);
  if (!defaultFeed) {
    throw new Error("Missing default OSV feed configuration.");
  }
  return defaultFeed;
};

// src/application/use-cases/types.ts
var buildSbomOverrideKey = (sbomId, originalName) => `${sbomId}::${originalName.trim()}`;

// src/application/settings/SettingsMigrator.ts
var componentPreferenceService = new ComponentPreferenceService();
var legacyNameNormalizer = new ProductNameNormalizer();
var normalizeStoredPath = (value) => value.replace(/\\/g, "/").split("/").filter((segment) => segment.length > 0).join("/");
var cloneFeedConfig = (feed) => ({ ...feed });
var normalizePositiveInteger = (value, fallback) => typeof value === "number" && Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
var normalizeBoundedPositiveInteger = (value, fallback, maximum) => Math.min(normalizePositiveInteger(value, fallback), maximum);
var normalizeFeedConfigs = (feeds) => (feeds ?? []).map((feed) => {
  if (feed.type === FEED_TYPES.NVD) {
    return {
      ...feed,
      dateFilterType: feed.dateFilterType === "published" ? "published" : "modified"
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
      )
    };
  }
  return { ...feed };
});
var normalizeStringList = (values) => {
  if (!Array.isArray(values)) {
    return [];
  }
  return Array.from(new Set(values.map((value) => typeof value === "string" ? value.trim() : "").filter((value) => value.length > 0)));
};
var normalizePathList = (values) => {
  if (!Array.isArray(values)) {
    return [];
  }
  return Array.from(new Set(values.map((value) => typeof value === "string" ? normalizeStoredPath(value.trim()) : "").filter((value) => value.length > 0)));
};
var buildLegacySbomLabel = (path) => {
  const normalized = normalizeStoredPath(path);
  const segments = normalized.split("/").filter(Boolean);
  const candidate = segments.at(-1);
  return candidate && candidate.length > 0 ? candidate : "SBOM";
};
var getTrimmedString = (value) => typeof value === "string" ? value.trim() : "";
var normalizeImportedSbomConfig = (sbom, index) => {
  const namespace = getTrimmedString(sbom.namespace);
  const contentHash = getTrimmedString(sbom.contentHash) || getTrimmedString(sbom.lastImportHash);
  const lastError = getTrimmedString(sbom.lastError) || getTrimmedString(sbom.lastImportError);
  const componentCount = typeof sbom.componentCount === "number" && Number.isFinite(sbom.componentCount) && sbom.componentCount >= 0 ? sbom.componentCount : void 0;
  const lastImportedAt = typeof sbom.lastImportedAt === "number" && Number.isFinite(sbom.lastImportedAt) ? sbom.lastImportedAt : 0;
  const linkedProjectNotePath = getTrimmedString(sbom.linkedProjectNotePath);
  const linkedProjectDisplayName = getTrimmedString(sbom.linkedProjectDisplayName);
  const normalized = {
    contentHash,
    enabled: sbom.enabled ?? true,
    id: getTrimmedString(sbom.id) || `sbom-${index + 1}`,
    label: getTrimmedString(sbom.label) || buildLegacySbomLabel(getTrimmedString(sbom.path)),
    lastImportedAt,
    path: getTrimmedString(sbom.path) ? normalizeStoredPath(getTrimmedString(sbom.path)) : ""
  };
  if (namespace) {
    normalized.namespace = namespace;
  }
  if (componentCount !== void 0) {
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
var createLegacySbomConfig = (path) => {
  const normalizedPath = normalizeStoredPath(path);
  return {
    contentHash: "",
    enabled: true,
    id: "sbom-1",
    label: buildLegacySbomLabel(normalizedPath),
    lastImportedAt: 0,
    path: normalizedPath
  };
};
var normalizeSbomOverride = (override) => {
  const editedName = getTrimmedString(override.editedName);
  const excluded = override.excluded === true;
  const normalized = {};
  if (editedName) {
    normalized.editedName = editedName;
  }
  if (excluded) {
    normalized.excluded = true;
  }
  return Object.keys(normalized).length > 0 ? normalized : null;
};
var normalizeSbomOverrides = (overrides) => {
  if (!overrides || typeof overrides !== "object") {
    return {};
  }
  const normalizedEntries = Object.entries(overrides).flatMap(([key, value]) => {
    const override = normalizeSbomOverride(value);
    return override ? [[key, override]] : [];
  });
  return Object.fromEntries(normalizedEntries);
};
var migrateLegacySbomOverrides = (sboms) => {
  const overrides = {};
  for (const [index, sbom] of sboms.entries()) {
    const normalizedSbom = normalizeImportedSbomConfig(sbom, index);
    const components = Array.isArray(sbom.components) ? sbom.components : [];
    for (const component of components) {
      const originalName = getTrimmedString(component.name) || getTrimmedString(component.normalizedName) || getTrimmedString(component.cpe) || getTrimmedString(component.purl) || getTrimmedString(component.bomRef);
      if (!originalName) {
        continue;
      }
      const editedName = getTrimmedString(component.normalizedName);
      const defaultName = legacyNameNormalizer.normalize(originalName) || originalName;
      const overrideInput = {
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
var normalizeCacheStorage = (value) => ({
  hardCap: typeof value?.hardCap === "number" && Number.isFinite(value.hardCap) && value.hardCap > 0 ? Math.floor(value.hardCap) : DEFAULT_CACHE_STORAGE.hardCap,
  hydrateMaxItems: typeof value?.hydrateMaxItems === "number" && Number.isFinite(value.hydrateMaxItems) && value.hydrateMaxItems > 0 ? Math.floor(value.hydrateMaxItems) : DEFAULT_CACHE_STORAGE.hydrateMaxItems,
  hydratePageSize: typeof value?.hydratePageSize === "number" && Number.isFinite(value.hydratePageSize) && value.hydratePageSize > 0 ? Math.floor(value.hydratePageSize) : DEFAULT_CACHE_STORAGE.hydratePageSize,
  pruneBatchSize: typeof value?.pruneBatchSize === "number" && Number.isFinite(value.pruneBatchSize) && value.pruneBatchSize > 0 ? Math.floor(value.pruneBatchSize) : DEFAULT_CACHE_STORAGE.pruneBatchSize,
  ttlMs: typeof value?.ttlMs === "number" && Number.isFinite(value.ttlMs) && value.ttlMs > 0 ? Math.floor(value.ttlMs) : DEFAULT_CACHE_STORAGE.ttlMs
});
var normalizeDailyRollupSettings = (value, legacy = {}) => {
  const severityThreshold = value?.severityThreshold ?? (legacy.autoHighNoteCreationEnabled === true ? "HIGH" : DEFAULT_DAILY_ROLLUP_SETTINGS.severityThreshold);
  const excludedTriageStates = Array.isArray(value?.excludedTriageStates) ? Array.from(new Set(value.excludedTriageStates.filter((state) => typeof state === "string" && state.length > 0))) : [...DEFAULT_DAILY_ROLLUP_SETTINGS.excludedTriageStates];
  const folderPath = typeof value?.folderPath === "string" && value.folderPath.trim().length > 0 ? normalizeStoredPath(value.folderPath.trim()) : typeof legacy.autoNoteFolder === "string" && legacy.autoNoteFolder.trim().length > 0 ? normalizeStoredPath(legacy.autoNoteFolder.trim()) : DEFAULT_DAILY_ROLLUP_SETTINGS.folderPath;
  return {
    autoGenerateOnFirstSyncOfDay: typeof value?.autoGenerateOnFirstSyncOfDay === "boolean" ? value.autoGenerateOnFirstSyncOfDay : legacy.autoNoteCreationEnabled === true || legacy.autoHighNoteCreationEnabled === true,
    excludedTriageStates,
    folderPath,
    includeUnmappedFindings: value?.includeUnmappedFindings ?? DEFAULT_DAILY_ROLLUP_SETTINGS.includeUnmappedFindings,
    lastAutoGeneratedOn: typeof value?.lastAutoGeneratedOn === "string" ? value.lastAutoGeneratedOn.trim() : "",
    severityThreshold
  };
};
var hasLegacyCursorKeys = (cursor) => Boolean(
  BUILT_IN_FEEDS.NVD.legacyCursorKey && cursor?.[BUILT_IN_FEEDS.NVD.legacyCursorKey] || BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey && cursor?.[BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey]
);
var migrateLegacySourceSyncCursor = (cursor) => {
  const normalized = { ...cursor ?? {} };
  const legacyNvdCursor = BUILT_IN_FEEDS.NVD.legacyCursorKey ? normalized[BUILT_IN_FEEDS.NVD.legacyCursorKey] : void 0;
  const legacyGithubCursor = BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey ? normalized[BUILT_IN_FEEDS.GITHUB_ADVISORY.legacyCursorKey] : void 0;
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
var migrateLegacyFeeds = (settings) => {
  const hasDynamicFeeds = Array.isArray(settings.feeds) && settings.feeds.length > 0;
  const feeds = hasDynamicFeeds ? normalizeFeedConfigs(settings.feeds) : DEFAULT_FEEDS.map((feed) => cloneFeedConfig(feed));
  if (!hasDynamicFeeds) {
    const nvdFeed = feeds.find((feed) => feed.type === FEED_TYPES.NVD && feed.id === BUILT_IN_FEEDS.NVD.id);
    if (nvdFeed && settings.nvdApiKey) {
      nvdFeed.apiKey = settings.nvdApiKey;
    }
    if (typeof settings.enableNvdFeed === "boolean" && nvdFeed) {
      nvdFeed.enabled = settings.enableNvdFeed;
    }
    const githubFeed = feeds.find((feed) => feed.type === FEED_TYPES.GITHUB_ADVISORY && feed.id === BUILT_IN_FEEDS.GITHUB_ADVISORY.id);
    if (githubFeed && settings.githubToken) {
      githubFeed.token = settings.githubToken;
    }
    if (typeof settings.enableGithubFeed === "boolean" && githubFeed) {
      githubFeed.enabled = settings.enableGithubFeed;
    }
  }
  return feeds;
};
var migrateLegacyProductFilters = (settings) => {
  const legacyProductFilters = normalizeStringList(settings.productFilters);
  const manualProductFilters = normalizeStringList(settings.manualProductFilters ?? legacyProductFilters);
  return {
    manualProductFilters,
    productFilters: normalizeStringList(manualProductFilters)
  };
};
var migrateLegacySbomSettings = (settings) => {
  const rawSboms = Array.isArray(settings.sboms) ? settings.sboms : [];
  const sboms = rawSboms.length > 0 ? rawSboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index)) : settings.sbomPath?.trim() ? [createLegacySbomConfig(settings.sbomPath)] : [];
  const migratedOverrides = migrateLegacySbomOverrides(rawSboms);
  return {
    sboms,
    sbomOverrides: normalizeSbomOverrides({
      ...migratedOverrides,
      ...settings.sbomOverrides ?? {}
    }),
    sbomPath: ""
  };
};
var normalizeRuntimeSettingsInternal = (settings) => ({
  ...componentPreferenceService.normalizeSettings(settings),
  keywordFilters: normalizeStringList(settings.keywordFilters),
  manualProductFilters: normalizeStringList(settings.manualProductFilters),
  productFilters: normalizeStringList(settings.productFilters),
  feeds: normalizeFeedConfigs(settings.feeds),
  sbomFolders: normalizePathList(settings.sbomFolders),
  sboms: settings.sboms.map((sbom, index) => normalizeImportedSbomConfig(sbom, index)),
  sbomOverrides: normalizeSbomOverrides(settings.sbomOverrides),
  dashboardDateField: settings.dashboardDateField === "published" ? "published" : "modified",
  triageFilter: normalizeTriageFilterMode(settings.triageFilter),
  dailyRollup: normalizeDailyRollupSettings(settings.dailyRollup),
  sbomPath: "",
  cacheStorage: normalizeCacheStorage(settings.cacheStorage),
  settingsVersion: SETTINGS_VERSION
});
var buildNormalizedSettings = (settings) => {
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
      ...settings.columnVisibility ?? {}
    },
    syncControls: {
      ...DEFAULT_SETTINGS.syncControls,
      ...settings.syncControls ?? {}
    },
    cacheStorage: normalizeCacheStorage(settings.cacheStorage)
  });
};
var defaultMigrationSteps = [
  {
    name: "legacy-feed-config",
    toVersion: 5,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 5 || !Array.isArray(settings.feeds) || settings.feeds.length === 0,
    migrate: (settings) => ({
      ...settings,
      feeds: migrateLegacyFeeds(settings)
    })
  },
  {
    name: "legacy-source-sync-cursors",
    toVersion: 6,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 6 || hasLegacyCursorKeys(settings.sourceSyncCursor),
    migrate: (settings) => ({
      ...settings,
      sourceSyncCursor: migrateLegacySourceSyncCursor(settings.sourceSyncCursor)
    })
  },
  {
    name: "legacy-product-filters",
    toVersion: 7,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 7,
    migrate: (settings) => ({
      ...settings,
      ...migrateLegacyProductFilters(settings)
    })
  },
  {
    name: "legacy-daily-rollup",
    toVersion: 8,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 8 || settings.autoHighNoteCreationEnabled === true || settings.autoNoteCreationEnabled === true || typeof settings.autoNoteFolder === "string" && settings.autoNoteFolder.trim().length > 0,
    migrate: (settings) => ({
      ...settings,
      dailyRollup: normalizeDailyRollupSettings(settings.dailyRollup, settings)
    })
  },
  {
    name: "legacy-sbom-settings",
    toVersion: 9,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 9 || Boolean(settings.sbomPath?.trim()),
    migrate: (settings) => ({
      ...settings,
      ...migrateLegacySbomSettings(settings)
    })
  }
];
var SettingsMigrator = class {
  constructor(steps = defaultMigrationSteps) {
    this.steps = steps;
  }
  migrate(settings) {
    const fromVersion = settings.settingsVersion ?? 0;
    let current = { ...settings };
    const appliedSteps = [];
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
  normalizeRuntimeSettings(settings) {
    return normalizeRuntimeSettingsInternal(settings);
  }
};
var defaultSettingsMigrator = new SettingsMigrator();
var migrateLegacySettings = (settings) => defaultSettingsMigrator.migrate(settings).settings;

// tests/application/settings/SettingsMigrator.test.ts
test("migrateLegacySettings defaults malformed component preference arrays safely", () => {
  const migrated = migrateLegacySettings({
    followedSbomComponentKeys: [" PURL:PKG:NPM/REACT@18.3.1 ", 7, null],
    disabledSbomComponentKeys: "invalid",
    sbomFolders: [" reports ", "", null],
    settingsVersion: 2
  });
  assert.deepEqual(migrated.followedSbomComponentKeys, ["purl:pkg:npm/react@18.3.1"]);
  assert.deepEqual(migrated.disabledSbomComponentKeys, []);
  assert.deepEqual(migrated.sbomFolders, ["reports"]);
  assert.equal(migrated.settingsVersion, SETTINGS_VERSION);
});
test("migrateLegacySettings maps legacy auto-note settings into the daily rollup configuration", () => {
  const migrated = migrateLegacySettings({
    autoHighNoteCreationEnabled: true,
    autoNoteCreationEnabled: true,
    autoNoteFolder: "Ops Briefings",
    settingsVersion: 7
  });
  assert.equal(migrated.dailyRollup.folderPath, "Ops Briefings");
  assert.equal(migrated.dailyRollup.autoGenerateOnFirstSyncOfDay, true);
  assert.equal(migrated.dailyRollup.severityThreshold, "HIGH");
});
test("migrateLegacySettings preserves legacy SBOM data and rekeys feed cursors without losing overrides", () => {
  const migrated = migrateLegacySettings({
    productFilters: ["Portal Web"],
    sbomPath: "reports/legacy.json",
    sboms: [
      {
        contentHash: "",
        components: [
          {
            excluded: true,
            name: "Portal Web",
            normalizedName: "Portal Control Plane"
          }
        ],
        enabled: true,
        id: "legacy-sbom",
        label: "Legacy SBOM",
        lastImportedAt: 0,
        path: "reports/legacy.json"
      }
    ],
    settingsVersion: 4,
    sourceSyncCursor: {
      GitHub: "github-cursor",
      NVD: "nvd-cursor"
    }
  });
  assert.deepEqual(migrated.manualProductFilters, ["Portal Web"]);
  assert.deepEqual(migrated.productFilters, ["Portal Web"]);
  assert.deepEqual(migrated.sboms, [{
    contentHash: "",
    enabled: true,
    id: "legacy-sbom",
    label: "Legacy SBOM",
    lastImportedAt: 0,
    path: "reports/legacy.json"
  }]);
  assert.deepEqual(migrated.sbomOverrides, {
    "legacy-sbom::Portal Web": {
      editedName: "Portal Control Plane",
      excluded: true
    }
  });
  assert.equal(migrated.sourceSyncCursor[BUILT_IN_FEEDS.NVD.id], "nvd-cursor");
  assert.equal(migrated.sourceSyncCursor[BUILT_IN_FEEDS.GITHUB_ADVISORY.id], "github-cursor");
  assert.equal(migrated.sourceSyncCursor.NVD, void 0);
  assert.equal(migrated.sourceSyncCursor.GitHub, void 0);
  assert.equal(migrated.settingsVersion, SETTINGS_VERSION);
});
test("migrateLegacySettings normalizes invalid OSV feed values predictably", () => {
  const migrated = migrateLegacySettings({
    feeds: [
      {
        id: BUILT_IN_FEEDS.OSV.id,
        name: BUILT_IN_FEEDS.OSV.name,
        type: FEED_TYPES.OSV,
        enabled: true,
        cacheTtlMs: 0,
        negativeCacheTtlMs: -1,
        requestTimeoutMs: Number.NaN,
        maxConcurrentBatches: 99
      }
    ]
  });
  const osvFeed = migrated.feeds.find((feed) => feed.type === FEED_TYPES.OSV);
  assert.ok(osvFeed);
  assert.equal(osvFeed?.enabled, true);
  assert.equal(osvFeed?.cacheTtlMs, 216e5);
  assert.equal(osvFeed?.negativeCacheTtlMs, 36e5);
  assert.equal(osvFeed?.requestTimeoutMs, 15e3);
  assert.equal(osvFeed?.maxConcurrentBatches, 8);
});
test("SettingsMigrator is idempotent for current settings", () => {
  const migrator = new SettingsMigrator();
  const result = migrator.migrate(DEFAULT_SETTINGS);
  assert.equal(result.didMigrate, false);
  assert.equal(result.fromVersion, SETTINGS_VERSION);
  assert.equal(result.toVersion, SETTINGS_VERSION);
  assert.deepEqual(result.appliedSteps, []);
  assert.deepEqual(result.settings, DEFAULT_SETTINGS);
});
