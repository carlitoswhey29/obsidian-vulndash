// tests/plugin.test.ts
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
var DEFAULT_OSV_ENDPOINT_URL = "https://api.osv.dev/v1/querybatch";
var DEFAULT_OSV_MAX_BATCH_SIZE = 1e3;
var MAX_CONFIGURABLE_OSV_BATCH_SIZE = 1e4;
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
    maxConcurrentBatches: 4,
    osvEndpointUrl: DEFAULT_OSV_ENDPOINT_URL,
    osvMaxBatchSize: DEFAULT_OSV_MAX_BATCH_SIZE
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
var SETTINGS_VERSION = 10;
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
var normalizeOsvEndpointUrl = (value, fallback = DEFAULT_OSV_ENDPOINT_URL) => {
  const candidate = typeof value === "string" ? value.trim() : "";
  if (!candidate) {
    return fallback;
  }
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return fallback;
    }
    return parsed.toString();
  } catch {
    return fallback;
  }
};
var normalizeOsvMaxBatchSize = (value, fallback = DEFAULT_OSV_MAX_BATCH_SIZE) => {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  const normalized = Math.floor(value);
  if (normalized < 1 || normalized > MAX_CONFIGURABLE_OSV_BATCH_SIZE) {
    return fallback;
  }
  return normalized;
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
      ),
      osvEndpointUrl: normalizeOsvEndpointUrl(feed.osvEndpointUrl, defaults.osvEndpointUrl),
      osvMaxBatchSize: normalizeOsvMaxBatchSize(feed.osvMaxBatchSize, defaults.osvMaxBatchSize)
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
  },
  {
    name: "osv-operational-config",
    toVersion: 10,
    shouldApply: (settings) => (settings.settingsVersion ?? 0) < 10,
    migrate: (settings) => ({
      ...settings,
      feeds: normalizeFeedConfigs(settings.feeds)
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
var buildPersistedSettingsSnapshot = (settings, secrets, feeds) => ({
  ...componentPreferenceService.normalizeSettings(settings),
  sbomOverrides: normalizeSbomOverrides(settings.sbomOverrides),
  sbomFolders: normalizePathList(settings.sbomFolders),
  sbomPath: "",
  settingsVersion: SETTINGS_VERSION,
  nvdApiKey: secrets.nvdApiKey,
  githubToken: secrets.githubToken,
  feeds
});

// tests/plugin.test.ts
test("buildPersistedSettingsSnapshot keeps persisted SBOM settings lean and normalized", () => {
  const snapshot = buildPersistedSettingsSnapshot({
    ...DEFAULT_SETTINGS,
    dailyRollup: {
      ...DEFAULT_SETTINGS.dailyRollup,
      folderPath: "briefings/daily"
    },
    manualProductFilters: ["Portal Web"],
    sbomFolders: ["reports", " reports ", "", "reports/nested"],
    followedSbomComponentKeys: ["PURL:PKG:NPM/LODASH@4.17.21", "purl:pkg:npm/lodash@4.17.21"],
    disabledSbomComponentKeys: [" name-version:legacy@1.0.0 ", "name-version:legacy@1.0.0"],
    productFilters: ["Portal Web", "Gateway Service"],
    sbomOverrides: {
      "sbom-1::portal-web": { editedName: "Portal Web" },
      "sbom-1::gateway": {}
    },
    sbomPath: "legacy/path.json"
  }, {
    githubToken: "encrypted-github",
    nvdApiKey: "encrypted-nvd"
  }, DEFAULT_SETTINGS.feeds.map((feed) => ({ ...feed })));
  assert.equal(snapshot.sbomPath, "");
  assert.equal(snapshot.settingsVersion, SETTINGS_VERSION);
  assert.equal(snapshot.nvdApiKey, "encrypted-nvd");
  assert.equal(snapshot.githubToken, "encrypted-github");
  assert.equal(snapshot.dailyRollup.folderPath, "briefings/daily");
  assert.deepEqual(snapshot.sbomFolders, ["reports", "reports/nested"]);
  assert.deepEqual(snapshot.followedSbomComponentKeys, ["purl:pkg:npm/lodash@4.17.21"]);
  assert.deepEqual(snapshot.disabledSbomComponentKeys, ["name-version:legacy@1.0.0"]);
  assert.deepEqual(snapshot.sbomOverrides, {
    "sbom-1::portal-web": { editedName: "Portal Web" }
  });
  assert.deepEqual(snapshot.manualProductFilters, ["Portal Web"]);
  assert.deepEqual(snapshot.productFilters, ["Portal Web", "Gateway Service"]);
});
test("default settings include a safe OSV feed configuration", () => {
  const osvFeed = DEFAULT_SETTINGS.feeds.find((feed) => feed.type === FEED_TYPES.OSV);
  assert.ok(osvFeed);
  assert.equal(osvFeed?.id, BUILT_IN_FEEDS.OSV.id);
  assert.equal(osvFeed?.enabled, false);
  assert.equal(osvFeed?.cacheTtlMs, 216e5);
  assert.equal(osvFeed?.negativeCacheTtlMs, 36e5);
  assert.equal(osvFeed?.requestTimeoutMs, 15e3);
  assert.equal(osvFeed?.maxConcurrentBatches, 4);
  assert.equal(osvFeed?.osvEndpointUrl, "https://api.osv.dev/v1/querybatch");
  assert.equal(osvFeed?.osvMaxBatchSize, 1e3);
});
