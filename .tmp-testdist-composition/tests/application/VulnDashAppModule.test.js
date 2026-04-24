// tests/application/VulnDashAppModule.test.ts
import assert from "node:assert/strict";
import test from "node:test";

// tests/support/obsidian-stub.ts
var normalizePath = (path) => path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");
var TAbstractFile = class {
  constructor() {
    this.path = "";
  }
};
var TFile = class extends TAbstractFile {
};
var requestUrl = async () => {
  throw new Error("requestUrl not implemented in test stub.");
};

// src/application/sbom/ComponentIdentityService.ts
var UNNAMED_COMPONENT_PATTERN = /^unnamed (component|package)( \d+)?$/i;
var normalizeToken = (value) => value.trim().replace(/\s+/g, " ").toLowerCase();
var normalizePurl = (value) => normalizeToken(value);
var normalizeCpe = (value) => normalizeToken(value);
var normalizeComponentName = (value) => {
  if (!value) {
    return void 0;
  }
  const normalized = normalizeToken(value);
  if (!normalized || UNNAMED_COMPONENT_PATTERN.test(normalized)) {
    return void 0;
  }
  return normalized;
};
var normalizeVersion = (value) => {
  if (!value) {
    return void 0;
  }
  const normalized = normalizeToken(value);
  return normalized || void 0;
};
var ComponentIdentityService = class {
  normalizePurlValue(value) {
    return normalizePurl(value);
  }
  normalizeCpeValue(value) {
    return normalizeCpe(value);
  }
  normalizeComponentNameValue(value) {
    return normalizeComponentName(value);
  }
  normalizeVersionValue(value) {
    return normalizeVersion(value);
  }
  getNameVersionKeyFromParts(name, version) {
    const normalizedName = normalizeComponentName(name);
    const normalizedVersion = normalizeVersion(version);
    if (!normalizedName || !normalizedVersion) {
      return null;
    }
    return `name-version:${normalizedName}@${normalizedVersion}`;
  }
  getCanonicalKey(component) {
    const purl = component.purl?.trim();
    if (purl) {
      return `purl:${normalizePurl(purl)}`;
    }
    const cpe = component.cpe?.trim();
    if (cpe) {
      return `cpe:${normalizeCpe(cpe)}`;
    }
    const name = normalizeComponentName(component.name);
    const version = normalizeVersion(component.version);
    if (name && version) {
      return `name-version:${name}@${version}`;
    }
    if (name) {
      return `name:${name}`;
    }
    const fallbackParts = [
      component.supplier,
      component.license,
      component.notePath ?? void 0
    ].map((value) => value?.trim()).filter((value) => Boolean(value)).map((value) => normalizeToken(value));
    if (fallbackParts.length > 0) {
      return `unresolved:${fallbackParts.join("|")}`;
    }
    return "unresolved:component";
  }
};

// src/application/sbom/RelationshipNormalizer.ts
var evidenceRank = {
  purl: 0,
  cpe: 1,
  "name-version": 2,
  explicit: 3
};
var compareStrings = (left, right) => left.localeCompare(right);
var compareOptionalStrings = (left, right) => (left ?? "").localeCompare(right ?? "");
var severityRank = (severity) => {
  switch (severity) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    default:
      return 0;
  }
};
var RelationshipNormalizer = class {
  constructor(identityService = new ComponentIdentityService()) {
    this.identityService = identityService;
  }
  buildVulnerabilityRef(vulnerability) {
    return `${this.normalizeVulnerabilityToken(vulnerability.source)}::${this.normalizeVulnerabilityToken(vulnerability.id)}`;
  }
  normalizeRelationshipGraph(relationships, componentsByKey, vulnerabilitiesByRef) {
    const dedupedByPair = /* @__PURE__ */ new Map();
    for (const relationship of relationships) {
      const normalized = this.normalizeRelationship(relationship);
      const pairKey = `${normalized.componentKey}||${normalized.vulnerabilityRef}`;
      const existing = dedupedByPair.get(pairKey);
      if (!existing || evidenceRank[normalized.evidence] < evidenceRank[existing.evidence]) {
        dedupedByPair.set(pairKey, normalized);
      }
    }
    const normalizedRelationships = Array.from(dedupedByPair.values()).sort(
      (left, right) => compareStrings(left.componentKey, right.componentKey) || compareStrings(left.vulnerabilityRef, right.vulnerabilityRef) || evidenceRank[left.evidence] - evidenceRank[right.evidence]
    );
    const componentsByVulnerability = /* @__PURE__ */ new Map();
    const vulnerabilitiesByComponent = /* @__PURE__ */ new Map();
    for (const relationship of normalizedRelationships) {
      const component = componentsByKey.get(relationship.componentKey);
      const vulnerability = vulnerabilitiesByRef.get(relationship.vulnerabilityRef);
      if (!component || !vulnerability) {
        continue;
      }
      const relatedComponent = this.toRelatedComponentSummary(component, relationship.evidence);
      const relatedVulnerability = this.toRelatedVulnerabilitySummary(vulnerability, relationship.evidence);
      const componentList = componentsByVulnerability.get(relationship.vulnerabilityRef) ?? [];
      componentList.push(relatedComponent);
      componentsByVulnerability.set(relationship.vulnerabilityRef, componentList);
      const vulnerabilityList = vulnerabilitiesByComponent.get(relationship.componentKey) ?? [];
      vulnerabilityList.push(relatedVulnerability);
      vulnerabilitiesByComponent.set(relationship.componentKey, vulnerabilityList);
    }
    for (const [key, entries] of componentsByVulnerability) {
      componentsByVulnerability.set(key, entries.sort(
        (left, right) => evidenceRank[left.evidence] - evidenceRank[right.evidence] || compareStrings(left.name, right.name) || compareOptionalStrings(left.version, right.version) || compareStrings(left.key, right.key)
      ));
    }
    for (const [key, entries] of vulnerabilitiesByComponent) {
      vulnerabilitiesByComponent.set(key, entries.sort(
        (left, right) => evidenceRank[left.evidence] - evidenceRank[right.evidence] || severityRank(right.severity) - severityRank(left.severity) || compareStrings(left.source, right.source) || compareStrings(left.id, right.id)
      ));
    }
    return {
      componentsByVulnerability,
      relationships: normalizedRelationships,
      vulnerabilitiesByComponent
    };
  }
  buildVulnerabilityIdentity(vulnerability, notePath) {
    const identifiers = new Set([
      vulnerability.id,
      vulnerability.metadata?.cveId ?? "",
      vulnerability.metadata?.ghsaId ?? "",
      ...vulnerability.metadata?.identifiers ?? [],
      ...vulnerability.metadata?.aliases ?? []
    ].map((value) => this.normalizeVulnerabilityToken(value)).filter(Boolean));
    return {
      id: vulnerability.id,
      identifiers: Array.from(identifiers).sort(compareStrings),
      ...notePath ? { notePath } : {},
      ref: this.buildVulnerabilityRef(vulnerability),
      source: vulnerability.source
    };
  }
  buildPurlKey(value) {
    return `purl:${this.identityService.normalizePurlValue(value)}`;
  }
  buildCpeKey(value) {
    return `cpe:${this.identityService.normalizeCpeValue(value)}`;
  }
  buildNameVersionKey(name, version) {
    return this.identityService.getNameVersionKeyFromParts(name, version);
  }
  normalizeVulnerabilityToken(value) {
    return value.trim().replace(/\s+/g, " ").toLowerCase();
  }
  normalizeRelationship(relationship) {
    return {
      componentKey: relationship.componentKey.trim().toLowerCase(),
      evidence: relationship.evidence,
      vulnerabilityId: relationship.vulnerabilityId.trim(),
      vulnerabilityRef: relationship.vulnerabilityRef.trim().toLowerCase(),
      vulnerabilitySource: relationship.vulnerabilitySource.trim()
    };
  }
  toRelatedComponentSummary(component, evidence) {
    const summary = {
      evidence,
      key: component.key,
      name: component.name,
      vulnerabilityCount: component.vulnerabilityCount
    };
    if (component.version) {
      summary.version = component.version;
    }
    if (component.purl) {
      summary.purl = component.purl;
    }
    if (component.cpe) {
      summary.cpe = component.cpe;
    }
    if (component.notePath !== void 0) {
      summary.notePath = component.notePath;
    }
    if (component.highestSeverity) {
      summary.highestSeverity = component.highestSeverity;
    }
    return summary;
  }
  toRelatedVulnerabilitySummary(vulnerability, evidence) {
    const summary = {
      cvssScore: vulnerability.cvssScore,
      evidence,
      id: vulnerability.id,
      referenceCount: vulnerability.references.length,
      severity: vulnerability.severity,
      source: vulnerability.source,
      title: vulnerability.title
    };
    if (vulnerability.notePath) {
      summary.notePath = vulnerability.notePath;
    }
    return summary;
  }
};

// src/domain/correlation/AffectedProjectResolution.ts
var EMPTY_AFFECTED_PROJECT_RESOLUTION = {
  affectedProjects: [],
  unmappedSboms: []
};

// src/application/correlation/ResolveAffectedProjects.ts
var compareAffectedProjects = (left, right) => left.status.localeCompare(right.status) || left.displayName.localeCompare(right.displayName) || left.notePath.localeCompare(right.notePath);
var compareUnmappedSboms = (left, right) => left.sbomLabel.localeCompare(right.sbomLabel) || left.sbomId.localeCompare(right.sbomId);
var ResolveAffectedProjects = class {
  constructor(mappingRepository, projectNoteLookup, relationshipNormalizer = new RelationshipNormalizer()) {
    this.mappingRepository = mappingRepository;
    this.projectNoteLookup = projectNoteLookup;
    this.relationshipNormalizer = relationshipNormalizer;
  }
  async execute(input) {
    if (input.vulnerabilities.length === 0) {
      return /* @__PURE__ */ new Map();
    }
    const mappings = await this.mappingRepository.list();
    const mappingsBySbomId = new Map(mappings.map((mapping) => [mapping.sbomId, mapping.projectNote]));
    const noteStates = await this.projectNoteLookup.getByPaths(mappings.map((mapping) => mapping.projectNote));
    const sbomsById = new Map(input.sboms.map((sbom) => [sbom.id, sbom]));
    const results = /* @__PURE__ */ new Map();
    for (const vulnerability of input.vulnerabilities) {
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
      const relatedComponents = input.relationships.componentsByVulnerability.get(vulnerabilityRef) ?? [];
      if (relatedComponents.length === 0) {
        results.set(vulnerabilityRef, EMPTY_AFFECTED_PROJECT_RESOLUTION);
        continue;
      }
      const matchedSbomIds = /* @__PURE__ */ new Set();
      for (const component of relatedComponents) {
        for (const sbomId of input.componentIndex.getSbomIdsForComponent(component.key)) {
          matchedSbomIds.add(sbomId);
        }
      }
      if (matchedSbomIds.size === 0) {
        results.set(vulnerabilityRef, EMPTY_AFFECTED_PROJECT_RESOLUTION);
        continue;
      }
      const aggregatedProjects = /* @__PURE__ */ new Map();
      const unmappedSboms = /* @__PURE__ */ new Map();
      for (const sbomId of matchedSbomIds) {
        const sbom = sbomsById.get(sbomId);
        if (!sbom) {
          continue;
        }
        const mapping = mappingsBySbomId.get(sbomId);
        if (!mapping) {
          unmappedSboms.set(sbomId, {
            sbomId,
            sbomLabel: sbom.label
          });
          continue;
        }
        const noteState = noteStates.get(mapping.notePath) ?? {
          displayName: mapping.displayName ?? sbom.label,
          notePath: mapping.notePath,
          status: "broken"
        };
        const existing = aggregatedProjects.get(noteState.notePath);
        if (existing) {
          existing.sourceSbomIds.add(sbom.id);
          existing.sourceSbomLabels.add(sbom.label);
          continue;
        }
        aggregatedProjects.set(noteState.notePath, {
          displayName: noteState.displayName,
          notePath: noteState.notePath,
          sourceSbomIds: /* @__PURE__ */ new Set([sbom.id]),
          sourceSbomLabels: /* @__PURE__ */ new Set([sbom.label]),
          status: noteState.status
        });
      }
      results.set(vulnerabilityRef, {
        affectedProjects: Array.from(aggregatedProjects.values()).map((project) => ({
          displayName: project.displayName,
          notePath: project.notePath,
          sourceSbomIds: Array.from(project.sourceSbomIds).sort((left, right) => left.localeCompare(right)),
          sourceSbomLabels: Array.from(project.sourceSbomLabels).sort((left, right) => left.localeCompare(right)),
          status: project.status
        })).sort(compareAffectedProjects),
        unmappedSboms: Array.from(unmappedSboms.values()).sort(compareUnmappedSboms)
      });
    }
    return results;
  }
};

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
var OPEN_TRIAGE_STATES = ["active", "investigating", "accepted_risk"];
var CLOSED_TRIAGE_STATES = ["mitigated", "false_positive", "suppressed"];
var TRIAGE_STATE_SET = new Set(TRIAGE_STATES);
var TRIAGE_STATE_LABELS = {
  active: "Active",
  investigating: "Investigating",
  accepted_risk: "Accepted Risk",
  mitigated: "Mitigated",
  false_positive: "False Positive",
  suppressed: "Suppressed"
};
var normalizeStateValue = (value) => value.trim().toLowerCase().replace(/[\s-]+/g, "_");
var isTriageState = (value) => typeof value === "string" && TRIAGE_STATE_SET.has(normalizeStateValue(value));
var parseTriageState = (value, fallback = DEFAULT_TRIAGE_STATE) => {
  if (typeof value !== "string") {
    return fallback;
  }
  const normalized = normalizeStateValue(value);
  return TRIAGE_STATE_SET.has(normalized) ? normalized : fallback;
};
var formatTriageStateLabel = (state) => TRIAGE_STATE_LABELS[state];
var isOpenTriageState = (state) => OPEN_TRIAGE_STATES.includes(state);

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
var FilterByTriageState = class {
  execute(items, mode) {
    if (mode === "all") {
      return [...items];
    }
    return items.filter((item) => this.matches(item.triageState, mode));
  }
  matches(state, mode) {
    switch (mode) {
      case "all":
        return true;
      case "active-only":
        return isOpenTriageState(state);
      case "hide-mitigated":
        return state !== "mitigated";
      default:
        return state === mode;
    }
  }
  resolve(state) {
    return state ?? DEFAULT_TRIAGE_STATE;
  }
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

// src/domain/value-objects/Severity.ts
var severityOrder = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};
var normalizedSeverityOrder = {
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5
};
var getSeverityRank = (severity) => severity ? normalizedSeverityOrder[severity] : 0;
var getHighestSeverity = (severities) => {
  let highest;
  for (const severity of severities) {
    if (getSeverityRank(severity) > getSeverityRank(highest)) {
      highest = severity;
    }
  }
  return highest;
};

// src/application/use-cases/EvaluateAlertsUseCase.ts
var AlertEngine = class {
  constructor() {
    this.triageFilter = new FilterByTriageState();
  }
  /**
   * Applies user-configured filtering rules in a deterministic order:
   * 1) numeric thresholds, 2) product filters, 3) keyword/regex filters, 4) triage state.
   */
  filter(vulnerabilities, settings, options = {}) {
    const keywords = settings.keywordFilters.map((value) => value.toLowerCase());
    const products = settings.productFilters.map((value) => value.toLowerCase());
    const minSeverityRank = severityOrder[settings.minSeverity];
    const regexFilters = settings.keywordRegexEnabled ? this.getRegexFilters(settings.keywordFilters) : [];
    const filtered = vulnerabilities.filter((vuln) => {
      if (vuln.cvssScore < settings.minCvssScore) return false;
      if (severityOrder[vuln.severity] < minSeverityRank) return false;
      const haystack = `${vuln.title} ${vuln.summary}`.toLowerCase();
      const productMatch = products.length === 0 || vuln.affectedProducts.some((product) => products.some((filter) => product.toLowerCase().includes(filter)));
      const keywordMatch = settings.keywordRegexEnabled ? regexFilters.length === 0 || regexFilters.some((keyword) => keyword.test(`${vuln.title} ${vuln.summary}`)) : keywords.length === 0 || keywords.some((keyword) => haystack.includes(keyword));
      return keywordMatch && productMatch;
    });
    const triageMode = settings.triageFilter;
    if (triageMode === "all") {
      return filtered;
    }
    const triageAware = filtered.map((vulnerability) => ({
      triageState: options.getTriageState?.(vulnerability) ?? DEFAULT_TRIAGE_STATE,
      vulnerability
    }));
    return this.triageFilter.execute(triageAware, triageMode).map((entry) => entry.vulnerability);
  }
  /**
   * Compiles case-insensitive regex filters from user input.
   * Invalid patterns are ignored so one bad rule does not disable filtering.
   */
  getRegexFilters(filters) {
    const regexFilters = [];
    for (const filter of filters) {
      try {
        regexFilters.push(new RegExp(filter, "i"));
      } catch {
      }
    }
    return regexFilters;
  }
};

// src/application/sbom/ComponentMergeService.ts
var normalizeToken2 = (value) => value.trim().replace(/\s+/g, " ").toLowerCase();
var compareOptionalStrings2 = (left, right) => {
  const leftValue = left?.trim() ?? "";
  const rightValue = right?.trim() ?? "";
  return leftValue.localeCompare(rightValue);
};
var pickDeterministicString = (left, right, options) => {
  const leftValue = left?.trim();
  const rightValue = right?.trim();
  if (!leftValue) {
    return rightValue || void 0;
  }
  if (!rightValue) {
    return leftValue;
  }
  const leftNormalized = normalizeToken2(leftValue);
  const rightNormalized = normalizeToken2(rightValue);
  if (leftNormalized === rightNormalized) {
    if (options?.preferLonger && leftValue.length !== rightValue.length) {
      return leftValue.length >= rightValue.length ? leftValue : rightValue;
    }
    return leftValue.localeCompare(rightValue) <= 0 ? leftValue : rightValue;
  }
  if (options?.preferLonger && leftValue.length !== rightValue.length) {
    return leftValue.length > rightValue.length ? leftValue : rightValue;
  }
  return leftNormalized.localeCompare(rightNormalized) <= 0 ? leftValue : rightValue;
};
var pickNotePath = (left, right) => {
  const leftValue = left?.trim();
  const rightValue = right?.trim();
  if (!leftValue) {
    return rightValue ?? null;
  }
  if (!rightValue) {
    return leftValue;
  }
  return leftValue.localeCompare(rightValue) <= 0 ? leftValue : rightValue;
};
var pickHighestSeverity = (left, right) => getHighestSeverity([left, right]);
var mergeNumbers = (left, right) => Array.from(/* @__PURE__ */ new Set([...left, ...right])).sort((first, second) => first - second);
var compareVulnerabilities = (left, right) => {
  const severityDiff = getSeverityRank(right.severity) - getSeverityRank(left.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }
  const scoreDiff = (right.score ?? -1) - (left.score ?? -1);
  if (scoreDiff !== 0) {
    return scoreDiff;
  }
  const idDiff = left.id.localeCompare(right.id);
  if (idDiff !== 0) {
    return idDiff;
  }
  return compareOptionalStrings2(left.vector, right.vector);
};
var buildCweGroups = (vulnerabilities) => {
  const groups = /* @__PURE__ */ new Map();
  for (const vulnerability of vulnerabilities) {
    for (const cwe of vulnerability.cwes) {
      const entries = groups.get(cwe) ?? /* @__PURE__ */ new Set();
      entries.add(vulnerability.id);
      groups.set(cwe, entries);
    }
  }
  return Array.from(groups.entries()).map(([cwe, vulnerabilityIds]) => ({
    count: vulnerabilityIds.size,
    cwe,
    vulnerabilityIds: Array.from(vulnerabilityIds).sort((left, right) => left.localeCompare(right))
  })).sort((left, right) => left.cwe - right.cwe);
};
var getVulnerabilityKey = (vulnerability) => {
  const normalizedId = normalizeToken2(vulnerability.id);
  if (normalizedId && normalizedId !== "unknown-vulnerability") {
    return `id:${normalizedId}`;
  }
  const bomRef = vulnerability.bomRef?.trim();
  if (bomRef) {
    return `bom-ref:${normalizeToken2(bomRef)}`;
  }
  const cwes = [...vulnerability.cwes].sort((left, right) => left - right).join(",");
  return [
    "fingerprint",
    normalizeToken2(vulnerability.sourceName ?? ""),
    vulnerability.severity ?? "",
    normalizeToken2(vulnerability.vector ?? ""),
    normalizeToken2(vulnerability.published ?? ""),
    cwes,
    normalizeToken2(vulnerability.description ?? "")
  ].join("|");
};
var mergeVulnerability = (left, right) => {
  const merged = {
    cwes: mergeNumbers(left.cwes, right.cwes),
    id: pickDeterministicString(left.id, right.id) ?? left.id
  };
  const bomRef = pickDeterministicString(left.bomRef, right.bomRef);
  if (bomRef) {
    merged.bomRef = bomRef;
  }
  const sourceName = pickDeterministicString(left.sourceName, right.sourceName);
  if (sourceName) {
    merged.sourceName = sourceName;
  }
  const sourceUrl = pickDeterministicString(left.sourceUrl, right.sourceUrl);
  if (sourceUrl) {
    merged.sourceUrl = sourceUrl;
  }
  const severity = pickHighestSeverity(left.severity, right.severity);
  if (severity) {
    merged.severity = severity;
  }
  const scoreCandidates = [left.score, right.score].filter((value) => value !== void 0);
  if (scoreCandidates.length > 0) {
    merged.score = Math.max(...scoreCandidates);
  }
  const method = pickDeterministicString(left.method, right.method);
  if (method) {
    merged.method = method;
  }
  const vector = pickDeterministicString(left.vector, right.vector);
  if (vector) {
    merged.vector = vector;
  }
  const description = pickDeterministicString(left.description, right.description, { preferLonger: true });
  if (description) {
    merged.description = description;
  }
  const publishedCandidates = [left.published, right.published].filter((value) => Boolean(value?.trim())).sort((first, second) => first.localeCompare(second));
  const earliestPublished = publishedCandidates[0];
  if (earliestPublished) {
    merged.published = earliestPublished;
  }
  const updatedCandidates = [left.updated, right.updated].filter((value) => Boolean(value?.trim())).sort((first, second) => second.localeCompare(first));
  const latestUpdated = updatedCandidates[0];
  if (latestUpdated) {
    merged.updated = latestUpdated;
  }
  return merged;
};
var compareSourceRecords = (left, right) => left.sourcePath.localeCompare(right.sourcePath) || left.format.localeCompare(right.format) || left.documentName.localeCompare(right.documentName) || left.name.localeCompare(right.name) || compareOptionalStrings2(left.version, right.version) || left.componentId.localeCompare(right.componentId);
var getSourceRecordKey = (source) => [
  source.sourcePath,
  source.format,
  source.documentName,
  source.name,
  source.version ?? "",
  source.componentId
].join("|");
var compareFormats = (left, right) => left.localeCompare(right);
var compareSourceFiles = (left, right) => left.localeCompare(right);
var ComponentMergeService = class {
  createTrackedComponent(key, input) {
    const { component, document } = input;
    const source = {
      componentId: component.id,
      documentName: document.name,
      format: document.format,
      name: component.name,
      sourcePath: document.sourcePath
    };
    if (component.version) {
      source.version = component.version;
    }
    if (component.purl) {
      source.purl = component.purl;
    }
    if (component.cpe) {
      source.cpe = component.cpe;
    }
    if (component.notePath !== void 0) {
      source.notePath = component.notePath;
    }
    const tracked = {
      cweGroups: buildCweGroups(component.vulnerabilities),
      formats: [document.format],
      isEnabled: true,
      isFollowed: false,
      key,
      name: component.name,
      sourceFiles: [document.sourcePath],
      sources: [source],
      vulnerabilities: [...component.vulnerabilities].sort(compareVulnerabilities),
      vulnerabilityCount: component.vulnerabilities.length
    };
    if (component.version) {
      tracked.version = component.version;
    }
    if (component.purl) {
      tracked.purl = component.purl;
    }
    if (component.cpe) {
      tracked.cpe = component.cpe;
    }
    if (component.supplier) {
      tracked.supplier = component.supplier;
    }
    if (component.license) {
      tracked.license = component.license;
    }
    if (component.notePath !== void 0) {
      tracked.notePath = component.notePath;
    }
    if (component.highestSeverity) {
      tracked.highestSeverity = component.highestSeverity;
    }
    return tracked;
  }
  mergeComponents(left, right) {
    const vulnerabilities = this.mergeVulnerabilities(left.vulnerabilities, right.vulnerabilities);
    const merged = {
      cweGroups: buildCweGroups(vulnerabilities),
      formats: Array.from(/* @__PURE__ */ new Set([...left.formats, ...right.formats])).sort(compareFormats),
      isEnabled: left.isEnabled && right.isEnabled,
      isFollowed: left.isFollowed || right.isFollowed,
      key: left.key,
      name: pickDeterministicString(left.name, right.name) ?? left.name,
      sourceFiles: Array.from(/* @__PURE__ */ new Set([...left.sourceFiles, ...right.sourceFiles])).sort(compareSourceFiles),
      sources: this.mergeSources(left.sources, right.sources),
      vulnerabilities,
      vulnerabilityCount: vulnerabilities.length
    };
    const version = pickDeterministicString(left.version, right.version);
    if (version) {
      merged.version = version;
    }
    const purl = pickDeterministicString(left.purl, right.purl);
    if (purl) {
      merged.purl = purl;
    }
    const cpe = pickDeterministicString(left.cpe, right.cpe);
    if (cpe) {
      merged.cpe = cpe;
    }
    const supplier = pickDeterministicString(left.supplier, right.supplier);
    if (supplier) {
      merged.supplier = supplier;
    }
    const license = pickDeterministicString(left.license, right.license);
    if (license) {
      merged.license = license;
    }
    const notePath = pickNotePath(left.notePath, right.notePath);
    if (notePath !== void 0) {
      merged.notePath = notePath;
    }
    const highestSeverity = getHighestSeverity([
      left.highestSeverity,
      right.highestSeverity,
      ...vulnerabilities.map((vulnerability) => vulnerability.severity)
    ]);
    if (highestSeverity) {
      merged.highestSeverity = highestSeverity;
    }
    return merged;
  }
  mergeSources(left, right) {
    const deduped = /* @__PURE__ */ new Map();
    for (const source of [...left, ...right]) {
      deduped.set(getSourceRecordKey(source), source);
    }
    return Array.from(deduped.values()).sort(compareSourceRecords);
  }
  mergeVulnerabilities(left, right) {
    const deduped = /* @__PURE__ */ new Map();
    for (const vulnerability of [...left, ...right]) {
      const key = getVulnerabilityKey(vulnerability);
      const existing = deduped.get(key);
      deduped.set(key, existing ? mergeVulnerability(existing, vulnerability) : vulnerability);
    }
    return Array.from(deduped.values()).sort(compareVulnerabilities);
  }
};

// src/application/sbom/SbomCatalogService.ts
var normalizeToken3 = (value) => value.trim().replace(/\s+/g, " ").toLowerCase();
var compareDocuments = (left, right) => left.sourcePath.localeCompare(right.sourcePath) || left.format.localeCompare(right.format) || left.name.localeCompare(right.name);
var compareTrackedComponents = (left, right) => {
  const severityDiff = getSeverityRank(right.highestSeverity) - getSeverityRank(left.highestSeverity);
  if (severityDiff !== 0) {
    return severityDiff;
  }
  return normalizeToken3(left.name).localeCompare(normalizeToken3(right.name)) || normalizeToken3(left.version ?? "").localeCompare(normalizeToken3(right.version ?? "")) || left.key.localeCompare(right.key);
};
var SbomCatalogService = class {
  constructor(identityService = new ComponentIdentityService(), mergeService = new ComponentMergeService()) {
    this.identityService = identityService;
    this.mergeService = mergeService;
  }
  buildCatalog(documents) {
    const sortedDocuments = [...documents].sort(compareDocuments);
    const trackedComponents = /* @__PURE__ */ new Map();
    const sourceFiles = /* @__PURE__ */ new Set();
    const formats = /* @__PURE__ */ new Set();
    for (const document of sortedDocuments) {
      sourceFiles.add(document.sourcePath);
      formats.add(document.format);
      for (const component of document.components) {
        const key = this.identityService.getCanonicalKey(component);
        const tracked = this.mergeService.createTrackedComponent(key, {
          component,
          document
        });
        const existing = trackedComponents.get(key);
        trackedComponents.set(
          key,
          existing ? this.mergeService.mergeComponents(existing, tracked) : tracked
        );
      }
    }
    const components = Array.from(trackedComponents.values()).sort(compareTrackedComponents);
    return {
      componentCount: components.length,
      components,
      formats: Array.from(formats).sort((left, right) => left.localeCompare(right)),
      sourceFiles: Array.from(sourceFiles).sort((left, right) => left.localeCompare(right))
    };
  }
};

// src/application/sbom/ComponentInventoryService.ts
var compareIssues = (left, right) => left.title.localeCompare(right.title) || (left.sourcePath ?? "").localeCompare(right.sourcePath ?? "") || left.sbomId.localeCompare(right.sbomId);
var ComponentInventoryService = class {
  constructor(catalogService = new SbomCatalogService(), preferenceService = new ComponentPreferenceService()) {
    this.catalogService = catalogService;
    this.preferenceService = preferenceService;
  }
  buildSnapshot(settings, loadResults) {
    const catalog = this.preferenceService.applyPreferences(
      this.catalogService.buildCatalog(this.collectDocuments(loadResults)),
      settings
    );
    const issues = this.collectIssues(settings, loadResults);
    return {
      catalog,
      configuredSbomCount: settings.sboms.length,
      enabledSbomCount: settings.sboms.filter((sbom) => sbom.enabled).length,
      failedSbomCount: issues.length,
      issues,
      parsedSbomCount: loadResults.filter((result) => result.success || result.cachedState).length
    };
  }
  collectDocuments(results) {
    return results.flatMap((result) => {
      if (result.success) {
        return [result.state.document];
      }
      return result.cachedState ? [result.cachedState.document] : [];
    });
  }
  collectIssues(settings, results) {
    const settingsById = new Map(settings.sboms.map((sbom) => [sbom.id, sbom]));
    return results.flatMap((result) => {
      if (result.success) {
        return [];
      }
      const sbom = settingsById.get(result.sbomId);
      if (!sbom) {
        return [];
      }
      const issue = {
        hasCachedData: result.cachedState !== null,
        message: result.error,
        sbomId: sbom.id,
        title: sbom.label || "Untitled SBOM"
      };
      const sourcePath = sbom.path.trim();
      if (sourcePath) {
        issue.sourcePath = sourcePath;
      }
      return [issue];
    }).sort(compareIssues);
  }
};

// src/application/sbom/ComponentVulnerabilityLinkService.ts
var ComponentVulnerabilityLinkService = class {
  constructor(normalizer = new RelationshipNormalizer()) {
    this.normalizer = normalizer;
  }
  buildGraph(components, vulnerabilities, options = {}) {
    const componentsByKey = new Map(components.map((component) => [component.key, component]));
    const vulnerabilitiesWithIdentity = vulnerabilities.map((vulnerability) => ({
      ...vulnerability,
      __identity: this.normalizer.buildVulnerabilityIdentity(
        vulnerability,
        options.getVulnerabilityNotePath?.(vulnerability)
      )
    }));
    const vulnerabilitiesByRef = new Map(vulnerabilitiesWithIdentity.map((vulnerability) => [
      vulnerability.__identity.ref,
      {
        ...vulnerability.__identity,
        cvssScore: vulnerability.cvssScore,
        references: vulnerability.references,
        severity: vulnerability.severity,
        title: vulnerability.title
      }
    ]));
    const vulnerabilitiesByPurl = this.indexByPurl(vulnerabilitiesWithIdentity);
    const vulnerabilitiesByCpe = this.indexByCpe(vulnerabilitiesWithIdentity);
    const vulnerabilitiesByNameVersion = this.indexByNameVersion(vulnerabilitiesWithIdentity);
    const vulnerabilitiesByIdentifier = this.indexByIdentifier(vulnerabilitiesWithIdentity);
    const relationships = [];
    for (const component of components) {
      const addMatches = (matches, evidence) => {
        if (!matches) {
          return;
        }
        for (const vulnerability of matches) {
          relationships.push({
            componentKey: component.key,
            evidence,
            vulnerabilityId: vulnerability.id,
            vulnerabilityRef: vulnerability.__identity.ref,
            vulnerabilitySource: vulnerability.source
          });
        }
      };
      if (component.purl) {
        addMatches(
          vulnerabilitiesByPurl.get(this.normalizer.buildPurlKey(component.purl)),
          "purl"
        );
      }
      if (component.cpe) {
        addMatches(
          vulnerabilitiesByCpe.get(this.normalizer.buildCpeKey(component.cpe)),
          "cpe"
        );
      }
      if (component.version) {
        const nameVersionKey = this.normalizer.buildNameVersionKey(component.name, component.version);
        if (nameVersionKey) {
          addMatches(vulnerabilitiesByNameVersion.get(nameVersionKey), "name-version");
        }
      }
      for (const embeddedVulnerability of component.vulnerabilities) {
        const identifiers = new Set([
          embeddedVulnerability.id,
          embeddedVulnerability.sourceName ?? ""
        ].map((value) => this.normalizer.normalizeVulnerabilityToken(value)).filter(Boolean));
        for (const identifier of identifiers) {
          addMatches(vulnerabilitiesByIdentifier.get(identifier), "explicit");
        }
      }
    }
    return this.normalizer.normalizeRelationshipGraph(
      relationships,
      componentsByKey,
      vulnerabilitiesByRef
    );
  }
  indexByPurl(vulnerabilities) {
    const index = /* @__PURE__ */ new Map();
    for (const vulnerability of vulnerabilities) {
      for (const affectedPackage of vulnerability.metadata?.affectedPackages ?? []) {
        const purl = affectedPackage.purl?.trim();
        if (!purl) {
          continue;
        }
        const key = this.normalizer.buildPurlKey(purl);
        const entries = index.get(key) ?? [];
        entries.push(vulnerability);
        index.set(key, entries);
      }
    }
    return index;
  }
  indexByCpe(vulnerabilities) {
    const index = /* @__PURE__ */ new Map();
    for (const vulnerability of vulnerabilities) {
      for (const affectedPackage of vulnerability.metadata?.affectedPackages ?? []) {
        const cpe = affectedPackage.cpe?.trim();
        if (!cpe) {
          continue;
        }
        const key = this.normalizer.buildCpeKey(cpe);
        const entries = index.get(key) ?? [];
        entries.push(vulnerability);
        index.set(key, entries);
      }
    }
    return index;
  }
  indexByNameVersion(vulnerabilities) {
    const index = /* @__PURE__ */ new Map();
    for (const vulnerability of vulnerabilities) {
      for (const affectedPackage of vulnerability.metadata?.affectedPackages ?? []) {
        if (!affectedPackage.version) {
          continue;
        }
        const key = this.normalizer.buildNameVersionKey(affectedPackage.name, affectedPackage.version);
        if (!key) {
          continue;
        }
        const entries = index.get(key) ?? [];
        entries.push(vulnerability);
        index.set(key, entries);
      }
    }
    return index;
  }
  indexByIdentifier(vulnerabilities) {
    const index = /* @__PURE__ */ new Map();
    for (const vulnerability of vulnerabilities) {
      for (const identifier of vulnerability.__identity.identifiers) {
        const entries = index.get(identifier) ?? [];
        entries.push(vulnerability);
        index.set(identifier, entries);
      }
    }
    return index;
  }
};

// src/application/use-cases/SbomComparisonService.ts
var SbomComparisonService = class {
  compare(left, right) {
    const leftValues = this.normalize(left);
    const rightValues = this.normalize(right);
    const leftSet = new Set(leftValues);
    const rightSet = new Set(rightValues);
    return {
      inBoth: leftValues.filter((value) => rightSet.has(value)),
      onlyInA: leftValues.filter((value) => !rightSet.has(value)),
      onlyInB: rightValues.filter((value) => !leftSet.has(value))
    };
  }
  normalize(values) {
    return Array.from(new Set(values.map((value) => value.trim()).filter((value) => value.length > 0))).sort((left, right) => left.localeCompare(right));
  }
};

// src/application/use-cases/SbomFilterMergeService.ts
var SbomFilterMergeService = class {
  merge(settings, runtimeCache) {
    const manualFilters = this.normalizeFilters(settings.manualProductFilters);
    const sbomFilters = this.normalizeFilters(settings.sboms.flatMap((sbom) => {
      const runtimeState = runtimeCache.get(sbom.id) ?? null;
      return this.getResolvedComponents(sbom, runtimeState, settings.sbomOverrides).filter((component) => !component.excluded).map((component) => component.displayName);
    }));
    if (settings.sbomImportMode === "replace") {
      return sbomFilters;
    }
    return this.normalizeFilters([...manualFilters, ...sbomFilters]);
  }
  getResolvedComponents(sbom, runtimeState, overrides) {
    if (!runtimeState) {
      return [];
    }
    return runtimeState.components.map((component) => {
      const override = overrides[buildSbomOverrideKey(sbom.id, component.originalName)];
      const editedName = override?.editedName?.trim() ?? "";
      const displayName = editedName || component.normalizedName.trim() || component.originalName.trim();
      return {
        displayName,
        ...editedName ? { editedName } : {},
        excluded: override?.excluded ?? false,
        normalizedName: component.normalizedName.trim() || component.originalName.trim(),
        originalName: component.originalName
      };
    }).sort((left, right) => left.displayName.localeCompare(right.displayName) || left.originalName.localeCompare(right.originalName));
  }
  normalizeFilters(filters) {
    return Array.from(new Set(filters.map((filter) => filter.trim()).filter((filter) => filter.length > 0))).sort((left, right) => left.localeCompare(right));
  }
};

// src/domain/services/PurlNormalizer.ts
var PurlNormalizer = class _PurlNormalizer {
  /**
   * Normalize a Package URL (PURL) into a deterministic canonical form.
   *
   * Normalization includes:
   * - Never throw on malformed input
   * - Normalize npm scoped packages (%40 -> @)
   * - Normalize casing for type / namespace / name
   * - Preserve version casing and content as much as possible
   * - Normalize qualifiers deterministically by lowercasing keys and sorting entries
   * - Keep delimiters structural: ?, &, =, #, /, @ are controlled only by reconstruction
   */
  static normalize(purl) {
    if (purl == null) {
      return void 0;
    }
    const raw = purl.trim();
    if (raw.length === 0) {
      return void 0;
    }
    if (!/^pkg:/i.test(raw)) {
      return _PurlNormalizer.safeLooseNormalize(raw);
    }
    const parsed = _PurlNormalizer.parsePurl(raw.substring(4));
    if (!parsed.type || !parsed.name) {
      return _PurlNormalizer.safeLooseNormalize(raw);
    }
    const type = _PurlNormalizer.normalizeType(parsed.type);
    const namespace = _PurlNormalizer.normalizeNamespace(parsed.namespace);
    const name = _PurlNormalizer.normalizeName(parsed.name);
    const version = _PurlNormalizer.normalizeVersion(parsed.version);
    const qualifiers = _PurlNormalizer.normalizeQualifiers(parsed.qualifiers);
    const subpath = _PurlNormalizer.normalizeSubpath(parsed.subpath);
    let normalized = `pkg:${type}/`;
    if (namespace) {
      normalized += `${namespace}/`;
    }
    normalized += name;
    if (version) {
      normalized += `@${version}`;
    }
    if (qualifiers) {
      normalized += `?${qualifiers}`;
    }
    if (subpath) {
      normalized += `#${subpath}`;
    }
    return normalized;
  }
  static parsePurl(value) {
    let working = value.trim();
    let subpath;
    const hashIndex = working.indexOf("#");
    if (hashIndex >= 0) {
      subpath = working.substring(hashIndex + 1);
      working = working.substring(0, hashIndex);
    }
    let qualifiers;
    const queryIndex = working.indexOf("?");
    if (queryIndex >= 0) {
      qualifiers = working.substring(queryIndex + 1);
      working = working.substring(0, queryIndex);
    }
    let version;
    const versionIndex = _PurlNormalizer.findVersionSeparator(working);
    if (versionIndex >= 0) {
      version = working.substring(versionIndex + 1);
      working = working.substring(0, versionIndex);
    }
    working = working.replace(/^\/+/, "").replace(/\/+$/, "");
    const firstSlash = working.indexOf("/");
    if (firstSlash < 0) {
      return {
        type: working,
        namespace: void 0,
        name: void 0,
        version,
        qualifiers,
        subpath
      };
    }
    const type = working.substring(0, firstSlash);
    const remainder = working.substring(firstSlash + 1);
    const pathSegments = remainder.split("/").map((segment) => segment.trim()).filter(Boolean);
    if (pathSegments.length === 0) {
      return {
        type,
        namespace: void 0,
        name: void 0,
        version,
        qualifiers,
        subpath
      };
    }
    const name = pathSegments[pathSegments.length - 1];
    const namespace = pathSegments.length > 1 ? pathSegments.slice(0, pathSegments.length - 1).join("/") : void 0;
    return {
      type,
      namespace,
      name,
      version,
      qualifiers,
      subpath
    };
  }
  /**
   * Find the @version separator, but avoid mistaking namespace scope markers
   * such as "@types" for a version delimiter.
   *
   * Examples:
   * - npm/@types/node@18.0.0  -> version separator is the last '@'
   * - npm/@angular/core       -> no version
   * - maven/org.example/app@1.0.0 -> version separator is the last '@'
   */
  static findVersionSeparator(value) {
    const lastAt = value.lastIndexOf("@");
    if (lastAt <= 0) {
      return -1;
    }
    const lastSlash = value.lastIndexOf("/");
    if (lastSlash > lastAt) {
      return -1;
    }
    return lastAt;
  }
  static normalizeType(type) {
    const decoded = _PurlNormalizer.safeDecode(type).trim().toLowerCase();
    return _PurlNormalizer.encodePathSegment(decoded);
  }
  static normalizeNamespace(namespace) {
    if (!namespace) {
      return void 0;
    }
    const normalized = namespace.split("/").map((segment) => _PurlNormalizer.safeDecode(segment).trim().toLowerCase()).filter(Boolean).map((segment) => _PurlNormalizer.encodePathSegment(segment, { preserveAtSign: true })).join("/");
    return normalized || void 0;
  }
  static normalizeName(name) {
    const decoded = _PurlNormalizer.safeDecode(name).trim().toLowerCase();
    return _PurlNormalizer.encodePathSegment(decoded, { preserveAtSign: true });
  }
  static normalizeVersion(version) {
    if (!version) {
      return void 0;
    }
    const decoded = _PurlNormalizer.safeDecode(version).trim();
    if (!decoded) {
      return void 0;
    }
    return _PurlNormalizer.encodeVersion(decoded);
  }
  static normalizeSubpath(subpath) {
    if (!subpath) {
      return void 0;
    }
    const normalized = subpath.split("/").map((segment) => _PurlNormalizer.safeDecode(segment).trim()).filter(Boolean).map((segment) => _PurlNormalizer.encodeSubpathSegment(segment)).join("/");
    return normalized || void 0;
  }
  static normalizeQualifiers(qualifiers) {
    if (!qualifiers) {
      return void 0;
    }
    const entries = [];
    for (const pair of qualifiers.split("&")) {
      const trimmedPair = pair.trim();
      if (!trimmedPair) {
        continue;
      }
      const eqIndex = trimmedPair.indexOf("=");
      let rawKey;
      let rawValue;
      if (eqIndex < 0) {
        rawKey = trimmedPair;
        rawValue = "";
      } else {
        rawKey = trimmedPair.substring(0, eqIndex);
        rawValue = trimmedPair.substring(eqIndex + 1);
      }
      const decodedKey = _PurlNormalizer.safeDecode(rawKey).trim().toLowerCase();
      const decodedValue = _PurlNormalizer.safeDecode(rawValue).trim();
      if (!decodedKey) {
        continue;
      }
      entries.push({
        decodedKey,
        decodedValue,
        encodedKey: _PurlNormalizer.encodeQualifierKey(decodedKey),
        encodedValue: _PurlNormalizer.encodeQualifierValue(decodedValue)
      });
    }
    if (entries.length === 0) {
      return void 0;
    }
    entries.sort((a, b) => {
      const keyCompare = a.decodedKey.localeCompare(b.decodedKey);
      if (keyCompare !== 0) {
        return keyCompare;
      }
      return a.decodedValue.localeCompare(b.decodedValue);
    });
    return entries.map((entry) => `${entry.encodedKey}=${entry.encodedValue}`).join("&");
  }
  /**
   * Safely decode a URI component. If malformed percent-encoding exists,
   * fall back to a targeted replacement strategy instead of throwing.
   */
  static safeDecode(value) {
    if (!value) {
      return value;
    }
    try {
      return decodeURIComponent(value);
    } catch {
      return value.replace(/%40/gi, "@").replace(/%2[fF]/g, "/").replace(/%3[aA]/g, ":").replace(/%23/gi, "#").replace(/%3[fF]/g, "?").replace(/%26/gi, "&").replace(/%3[dD]/g, "=").replace(/%2[bB]/g, "+").replace(/%25/gi, "%").replace(/%20/gi, " ");
    }
  }
  /**
   * For non-PURL or malformed PURL-like strings, normalize loosely enough
   * to support deterministic matching without pretending strict spec fidelity.
   */
  static safeLooseNormalize(value) {
    const decoded = _PurlNormalizer.safeDecode(value).trim().replace(/\s+/g, " ");
    if (!decoded) {
      return void 0;
    }
    return decoded.replace(/\/{2,}/g, "/");
  }
  /**
   * Encode a path segment. Structural '/' is not allowed inside a segment.
   * For npm scopes in namespace/name, we preserve '@' for readability and matching.
   */
  static encodePathSegment(value, options) {
    let encoded = encodeURIComponent(value);
    if (options?.preserveAtSign) {
      encoded = encoded.replace(/%40/gi, "@");
    }
    return encoded;
  }
  /**
   * Encode a version conservatively. We do not lowercase it.
   */
  static encodeVersion(value) {
    return encodeURIComponent(value);
  }
  /**
   * Encode a qualifier key. Keys are already lowercased before this point.
   */
  static encodeQualifierKey(value) {
    return encodeURIComponent(value);
  }
  /**
   * Encode a qualifier value safely so that '&' and '=' remain data, not delimiters.
   */
  static encodeQualifierValue(value) {
    return encodeURIComponent(value);
  }
  /**
   * Encode a subpath segment conservatively. '/' is handled structurally by join().
   */
  static encodeSubpathSegment(value) {
    return encodeURIComponent(value);
  }
};

// src/infrastructure/parsers/CycloneDxParser.ts
var isRecord = (value) => typeof value === "object" && value !== null;
var getTrimmedString2 = (value) => {
  if (typeof value !== "string") {
    return void 0;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : void 0;
};
var getFiniteNumber = (value) => typeof value === "number" && Number.isFinite(value) ? value : void 0;
var normalizeSeverity = (severity) => {
  const normalized = getTrimmedString2(severity)?.toLowerCase();
  switch (normalized) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "info":
    case "informational":
      return "informational";
    default:
      return void 0;
  }
};
var compareVulnerabilities2 = (left, right) => {
  const severityDiff = getSeverityRank(right.severity) - getSeverityRank(left.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }
  const rightScore = right.score ?? -1;
  const leftScore = left.score ?? -1;
  if (rightScore !== leftScore) {
    return rightScore - leftScore;
  }
  return left.id.localeCompare(right.id);
};
var buildCweGroups2 = (vulnerabilities) => {
  const groups = /* @__PURE__ */ new Map();
  for (const vulnerability of vulnerabilities) {
    for (const cwe of vulnerability.cwes) {
      const current = groups.get(cwe) ?? /* @__PURE__ */ new Set();
      current.add(vulnerability.id);
      groups.set(cwe, current);
    }
  }
  return Array.from(groups.entries()).map(([cwe, vulnerabilityIds]) => ({
    count: vulnerabilityIds.size,
    cwe,
    vulnerabilityIds: Array.from(vulnerabilityIds).sort((left, right) => left.localeCompare(right))
  })).sort((left, right) => left.cwe - right.cwe);
};
var buildVulnerabilitySummary = (vulnerabilities) => {
  const cweIds = /* @__PURE__ */ new Set();
  const severities = /* @__PURE__ */ new Set();
  for (const vulnerability of vulnerabilities) {
    for (const cwe of vulnerability.cwes) {
      cweIds.add(cwe);
    }
    if (vulnerability.severity) {
      severities.add(vulnerability.severity);
    }
  }
  const summary = {
    cweIds: Array.from(cweIds).sort((left, right) => left - right),
    severities: Array.from(severities).sort((left, right) => getSeverityRank(right) - getSeverityRank(left)),
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilityIds: vulnerabilities.map((vulnerability) => vulnerability.id)
  };
  const highestSeverity = getHighestSeverity(vulnerabilities.map((vulnerability) => vulnerability.severity));
  if (highestSeverity) {
    summary.highestSeverity = highestSeverity;
  }
  return summary;
};
var buildEmptyVulnerabilitySummary = () => ({
  cweIds: [],
  severities: [],
  vulnerabilityCount: 0,
  vulnerabilityIds: []
});
var flattenComponents = (bom) => {
  const queue = [];
  const metadata = isRecord(bom.metadata) ? bom.metadata : null;
  if (isRecord(metadata?.component)) {
    queue.push(metadata.component);
  }
  if (Array.isArray(bom.components)) {
    queue.push(...bom.components.filter(isRecord));
  }
  const flattened = [];
  while (queue.length > 0) {
    const component = queue.shift();
    if (!component) {
      continue;
    }
    flattened.push(component);
    if (Array.isArray(component.components)) {
      queue.push(...component.components.filter(isRecord));
    }
  }
  return flattened;
};
var getPrimaryLicense = (component) => {
  if (!Array.isArray(component.licenses)) {
    return void 0;
  }
  for (const entry of component.licenses) {
    if (!isRecord(entry)) {
      continue;
    }
    const licenseChoice = entry;
    const expression = getTrimmedString2(licenseChoice.expression);
    if (expression) {
      return expression;
    }
    if (!isRecord(licenseChoice.license)) {
      continue;
    }
    const license = licenseChoice.license;
    const id = getTrimmedString2(license.id);
    if (id) {
      return id;
    }
    const name = getTrimmedString2(license.name);
    if (name) {
      return name;
    }
  }
  return void 0;
};
var normalizeCycloneDxVulnerability = (vulnerability) => {
  const firstRating = Array.isArray(vulnerability.ratings) ? vulnerability.ratings.find((rating) => isRecord(rating)) : void 0;
  const vulnerabilitySource = isRecord(vulnerability.source) ? vulnerability.source : void 0;
  const ratingSource = isRecord(firstRating?.source) ? firstRating.source : void 0;
  const normalized = {
    cwes: Array.isArray(vulnerability.cwes) ? vulnerability.cwes.filter((cwe) => typeof cwe === "number" && Number.isInteger(cwe)) : [],
    id: getTrimmedString2(vulnerability.id) ?? getTrimmedString2(vulnerability["bom-ref"]) ?? "unknown-vulnerability"
  };
  const bomRef = getTrimmedString2(vulnerability["bom-ref"]);
  if (bomRef) {
    normalized.bomRef = bomRef;
  }
  const sourceName = getTrimmedString2(vulnerabilitySource?.name) ?? getTrimmedString2(ratingSource?.name);
  if (sourceName) {
    normalized.sourceName = sourceName;
  }
  const sourceUrl = getTrimmedString2(vulnerabilitySource?.url) ?? getTrimmedString2(ratingSource?.url);
  if (sourceUrl) {
    normalized.sourceUrl = sourceUrl;
  }
  const severity = normalizeSeverity(firstRating?.severity);
  if (severity) {
    normalized.severity = severity;
  }
  const score = getFiniteNumber(firstRating?.score);
  if (score !== void 0) {
    normalized.score = score;
  }
  const method = getTrimmedString2(firstRating?.method);
  if (method) {
    normalized.method = method;
  }
  const vector = getTrimmedString2(firstRating?.vector);
  if (vector) {
    normalized.vector = vector;
  }
  const description = getTrimmedString2(vulnerability.description);
  if (description) {
    normalized.description = description;
  }
  const published = getTrimmedString2(vulnerability.published);
  if (published) {
    normalized.published = published;
  }
  const updated = getTrimmedString2(vulnerability.updated);
  if (updated) {
    normalized.updated = updated;
  }
  return normalized;
};
var buildVulnerabilityIndex = (bom) => {
  const index = /* @__PURE__ */ new Map();
  const vulnerabilities = Array.isArray(bom.vulnerabilities) ? bom.vulnerabilities.filter(isRecord) : [];
  for (const vulnerability of vulnerabilities) {
    const normalized = normalizeCycloneDxVulnerability(vulnerability);
    const affects = Array.isArray(vulnerability.affects) ? vulnerability.affects.filter(isRecord) : [];
    for (const affected of affects) {
      const ref = getTrimmedString2(affected.ref);
      if (!ref) {
        continue;
      }
      const entries = index.get(ref) ?? /* @__PURE__ */ new Map();
      entries.set(normalized.id, normalized);
      index.set(ref, entries);
    }
  }
  return new Map(Array.from(index.entries()).map(([ref, vulnerabilities2]) => [
    ref,
    Array.from(vulnerabilities2.values()).sort(compareVulnerabilities2)
  ]));
};
var isCycloneDxJson = (value) => {
  if (!isRecord(value)) {
    return false;
  }
  const bomFormat = getTrimmedString2(value.bomFormat)?.toLowerCase();
  if (bomFormat === "cyclonedx") {
    return true;
  }
  const hasSpecVersion = getTrimmedString2(value.specVersion) !== void 0;
  const hasComponents = Array.isArray(value.components);
  const hasVulnerabilities = Array.isArray(value.vulnerabilities);
  const metadata = isRecord(value.metadata) ? value.metadata : null;
  const hasMetadataComponent = isRecord(metadata?.component);
  return hasSpecVersion && (hasComponents || hasVulnerabilities || hasMetadataComponent);
};
var parseCycloneDxJson = (bom, options) => {
  const vulnerabilityIndex = buildVulnerabilityIndex(bom);
  const components = flattenComponents(bom).map((component, index) => {
    const name = getTrimmedString2(component.name) ?? `Unnamed component ${index + 1}`;
    const version = getTrimmedString2(component.version);
    const componentRef = getTrimmedString2(component["bom-ref"]);
    const vulnerabilities = componentRef ? [...vulnerabilityIndex.get(componentRef) ?? []] : [];
    const vulnerabilitySummary = vulnerabilities.length > 0 ? buildVulnerabilitySummary(vulnerabilities) : buildEmptyVulnerabilitySummary();
    const highestSeverity = vulnerabilitySummary.highestSeverity;
    const supplier = isRecord(component.supplier) ? getTrimmedString2(component.supplier.name) : void 0;
    const purl = getTrimmedString2(component.purl);
    const cpe = getTrimmedString2(component.cpe);
    const normalized = {
      cweGroups: buildCweGroups2(vulnerabilities),
      id: componentRef ?? `${name}@${version ?? "unknown"}#${index}`,
      name,
      vulnerabilitySummary,
      vulnerabilities,
      vulnerabilityCount: vulnerabilities.length
    };
    if (version) {
      normalized.version = version;
    }
    if (supplier) {
      normalized.supplier = supplier;
    }
    const license = getPrimaryLicense(component);
    if (license) {
      normalized.license = license;
    }
    if (purl) {
      normalized.purl = PurlNormalizer.normalize(purl);
    }
    if (cpe) {
      normalized.cpe = cpe;
    }
    if (highestSeverity) {
      normalized.highestSeverity = highestSeverity;
    }
    if (options.resolveNotePath) {
      const noteInput = { name };
      if (cpe) {
        noteInput.cpe = cpe;
      }
      if (purl) {
        noteInput.purl = purl;
      }
      if (version) {
        noteInput.version = version;
      }
      const notePath = options.resolveNotePath(noteInput);
      if (notePath !== void 0) {
        normalized.notePath = notePath;
      }
    }
    return normalized;
  });
  const metadata = isRecord(bom.metadata) ? bom.metadata : null;
  const metadataComponent = isRecord(metadata?.component) ? metadata.component : void 0;
  return {
    components,
    format: "cyclonedx",
    name: getTrimmedString2(metadataComponent?.name) ?? options.source.basename,
    sourcePath: options.source.path
  };
};

// src/infrastructure/parsers/SpdxParser.ts
var isRecord2 = (value) => typeof value === "object" && value !== null;
var getTrimmedString3 = (value) => {
  if (typeof value !== "string") {
    return void 0;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : void 0;
};
var buildEmptyVulnerabilitySummary2 = () => ({
  cweIds: [],
  severities: [],
  vulnerabilityCount: 0,
  vulnerabilityIds: []
});
var getExternalReference = (pkg, matcher) => {
  if (!Array.isArray(pkg.externalRefs)) {
    return void 0;
  }
  for (const reference of pkg.externalRefs) {
    if (!isRecord2(reference)) {
      continue;
    }
    const normalizedReference = reference;
    const referenceType = getTrimmedString3(normalizedReference.referenceType)?.toLowerCase();
    if (!referenceType || !matcher(referenceType)) {
      continue;
    }
    const locator = getTrimmedString3(normalizedReference.referenceLocator);
    if (locator) {
      return locator;
    }
  }
  return void 0;
};
var isSpdxJson = (value) => {
  if (!isRecord2(value)) {
    return false;
  }
  const spdxVersion = getTrimmedString3(value.spdxVersion);
  if (spdxVersion?.toUpperCase().startsWith("SPDX-")) {
    return true;
  }
  const spdxId = getTrimmedString3(value.SPDXID);
  if (spdxId === "SPDXRef-DOCUMENT") {
    return true;
  }
  return Array.isArray(value.packages) && isRecord2(value.creationInfo);
};
var parseSpdxJson = (document, options) => {
  const packages = Array.isArray(document.packages) ? document.packages.filter(isRecord2) : [];
  const components = packages.map((pkg, index) => {
    const name = getTrimmedString3(pkg.name) ?? `Unnamed package ${index + 1}`;
    const version = getTrimmedString3(pkg.versionInfo);
    const purl = getExternalReference(pkg, (referenceType) => referenceType.includes("purl"));
    const cpe = getExternalReference(pkg, (referenceType) => referenceType.includes("cpe"));
    const license = getTrimmedString3(pkg.licenseDeclared) ?? getTrimmedString3(pkg.licenseConcluded);
    const normalized = {
      cweGroups: [],
      id: getTrimmedString3(pkg.SPDXID) ?? `${name}@${version ?? "unknown"}#${index}`,
      name,
      vulnerabilitySummary: buildEmptyVulnerabilitySummary2(),
      vulnerabilities: [],
      vulnerabilityCount: 0
    };
    if (version) {
      normalized.version = version;
    }
    const supplier = getTrimmedString3(pkg.supplier);
    if (supplier) {
      normalized.supplier = supplier;
    }
    if (license) {
      normalized.license = license;
    }
    if (purl) {
      normalized.purl = PurlNormalizer.normalize(purl);
    }
    if (cpe) {
      normalized.cpe = cpe;
    }
    if (options.resolveNotePath) {
      const noteInput = { name };
      if (cpe) {
        noteInput.cpe = cpe;
      }
      if (purl) {
        noteInput.purl = purl;
      }
      if (version) {
        noteInput.version = version;
      }
      const notePath = options.resolveNotePath(noteInput);
      if (notePath !== void 0) {
        normalized.notePath = notePath;
      }
    }
    return normalized;
  });
  return {
    components,
    format: "spdx",
    name: getTrimmedString3(document.name) ?? options.source.basename,
    sourcePath: options.source.path
  };
};

// src/infrastructure/parsers/index.ts
var parseSbomJson = (json, options) => {
  if (isCycloneDxJson(json)) {
    return parseCycloneDxJson(json, options);
  }
  if (isSpdxJson(json)) {
    return parseSpdxJson(json, options);
  }
  throw new Error(
    `Unsupported SBOM JSON format in "${options.source.path}". Supported formats: CycloneDX JSON and SPDX JSON.`
  );
};

// src/infrastructure/async/CooperativeScheduler.ts
var CooperativeScheduler = class {
  async mapInBatches(values, iteratee, options = {}) {
    const outputs = [];
    let processedSinceYield = 0;
    for (const [index, value] of values.entries()) {
      this.throwIfAborted(options.signal);
      outputs.push(iteratee(value, index));
      processedSinceYield += 1;
      if (processedSinceYield >= (options.itemsPerYield ?? 100)) {
        processedSinceYield = 0;
        await this.yieldToHost(options);
      }
    }
    return outputs;
  }
  async maybeYield(processedSinceYield, options = {}) {
    if (processedSinceYield < (options.itemsPerYield ?? 100)) {
      return;
    }
    await this.yieldToHost(options);
  }
  async yieldToHost(options = {}) {
    this.throwIfAborted(options.signal);
    await new Promise((resolve) => {
      if (typeof globalThis.requestIdleCallback === "function") {
        globalThis.requestIdleCallback(() => resolve(), { timeout: options.timeoutMs ?? 16 });
        return;
      }
      globalThis.setTimeout(resolve, 0);
    });
  }
  throwIfAborted(signal) {
    if (signal?.aborted) {
      throw new Error("Async task aborted.");
    }
  }
};

// src/infrastructure/async/WorkerBundleRegistry.ts
var WORKER_BUNDLE_LOADERS = {
  "normalize-vulnerabilities": async () => {
    const module = await import("virtual:vulndash-worker/normalize");
    return module.default;
  },
  "parse-sbom": async () => {
    const module = await import("virtual:vulndash-worker/sbomParse");
    return module.default;
  }
};

// src/infrastructure/async/WorkerFactory.ts
var WorkerFactory = class {
  constructor() {
    this.unavailableKinds = /* @__PURE__ */ new Set();
  }
  async create(taskKind) {
    if (this.unavailableKinds.has(taskKind) || typeof Worker !== "function" || typeof Blob === "undefined" || typeof URL.createObjectURL !== "function") {
      return null;
    }
    try {
      const workerCode = await WORKER_BUNDLE_LOADERS[taskKind]();
      const blobUrl = URL.createObjectURL(new Blob([workerCode], {
        type: "text/javascript"
      }));
      const worker = new Worker(blobUrl, {
        name: `vulndash-${taskKind}`
      });
      return {
        dispose: () => {
          worker.terminate();
          URL.revokeObjectURL(blobUrl);
        },
        worker
      };
    } catch (error) {
      this.unavailableKinds.add(taskKind);
      console.warn("[vulndash.async.worker_unavailable]", {
        error: error instanceof Error ? error.message : "unknown_worker_error",
        taskKind
      });
      return null;
    }
  }
};

// src/infrastructure/async/AsyncTaskCoordinator.ts
var WorkerClient = class {
  constructor(taskKind, handle) {
    this.taskKind = taskKind;
    this.handle = handle;
    this.nextRequestId = 1;
    this.pending = /* @__PURE__ */ new Map();
    this.handle.worker.addEventListener("error", (event) => {
      const error = event.error instanceof Error ? event.error : new Error(event.message || `Worker task "${this.taskKind}" failed.`);
      this.rejectAll(error);
    });
    this.handle.worker.addEventListener("message", (event) => {
      this.handleMessage(event.data);
    });
  }
  dispose() {
    this.rejectAll(new Error(`Worker task "${this.taskKind}" was disposed.`));
    this.handle.dispose();
  }
  post(payload) {
    const requestId = this.nextRequestId++;
    const message = {
      payload,
      requestId,
      taskKind: this.taskKind
    };
    return new Promise((resolve, reject) => {
      this.pending.set(requestId, {
        reject,
        resolve
      });
      this.handle.worker.postMessage(message);
    });
  }
  handleMessage(message) {
    if (message.taskKind !== this.taskKind) {
      return;
    }
    const pending = this.pending.get(message.requestId);
    if (!pending) {
      return;
    }
    this.pending.delete(message.requestId);
    if (message.success) {
      pending.resolve(message.result);
      return;
    }
    pending.reject(new Error(message.error));
  }
  rejectAll(error) {
    const pendingRequests = Array.from(this.pending.values());
    this.pending.clear();
    for (const pending of pendingRequests) {
      pending.reject(error);
    }
  }
};
var AsyncTaskCoordinator = class {
  constructor(workerFactory = new WorkerFactory(), scheduler = new CooperativeScheduler()) {
    this.tokens = /* @__PURE__ */ new Map();
    this.workerClients = /* @__PURE__ */ new Map();
    this.workerFactory = workerFactory;
    this.scheduler = scheduler;
  }
  beginToken(key) {
    const generation = (this.tokens.get(key) ?? 0) + 1;
    this.tokens.set(key, generation);
    return {
      generation,
      key
    };
  }
  dispose() {
    for (const client of this.workerClients.values()) {
      client.dispose();
    }
    this.workerClients.clear();
  }
  async execute(taskKind, payload, options) {
    if (options.preferWorker !== false) {
      const workerClient = await this.getWorkerClient(taskKind);
      if (workerClient) {
        try {
          return await workerClient.post(payload);
        } catch (error) {
          this.disposeWorkerClient(taskKind);
          console.warn("[vulndash.async.worker_fallback]", {
            error: error instanceof Error ? error.message : "unknown_worker_error",
            taskKind
          });
        }
      }
    }
    return options.fallback(payload, this.scheduler);
  }
  isCurrent(token) {
    return this.tokens.get(token.key) === token.generation;
  }
  releaseToken(token) {
    if (this.isCurrent(token)) {
      this.tokens.delete(token.key);
    }
  }
  disposeWorkerClient(taskKind) {
    const client = this.workerClients.get(taskKind);
    if (!client) {
      return;
    }
    client.dispose();
    this.workerClients.delete(taskKind);
  }
  async getWorkerClient(taskKind) {
    const existingClient = this.workerClients.get(taskKind);
    if (existingClient) {
      return existingClient;
    }
    const workerHandle = await this.workerFactory.create(taskKind);
    if (!workerHandle) {
      return null;
    }
    const client = new WorkerClient(taskKind, workerHandle);
    this.workerClients.set(taskKind, client);
    return client;
  }
};

// src/application/use-cases/SbomImportService.ts
var DEFAULT_NOTE_PATH_ITEMS_PER_YIELD = 100;
var DEFAULT_RUNTIME_COMPONENT_ITEMS_PER_YIELD = 150;
var DEFAULT_SBOM_WORKER_MINIMUM_BYTES = 512 * 1024;
var SbomImportService = class {
  constructor(reader, nameNormalizer = new ProductNameNormalizer(), notePathResolverFactory = null, options = {}) {
    this.runtimeCache = /* @__PURE__ */ new Map();
    this.reader = reader;
    this.nameNormalizer = nameNormalizer;
    this.notePathResolverFactory = notePathResolverFactory;
    this.asyncTaskCoordinator = options.asyncTaskCoordinator ?? new AsyncTaskCoordinator();
    this.cooperativeScheduler = options.cooperativeScheduler ?? new CooperativeScheduler();
    this.notePathItemsPerYield = options.notePathItemsPerYield ?? DEFAULT_NOTE_PATH_ITEMS_PER_YIELD;
    this.runtimeComponentItemsPerYield = options.runtimeComponentItemsPerYield ?? DEFAULT_RUNTIME_COMPONENT_ITEMS_PER_YIELD;
    this.workerMinimumBytes = options.workerMinimumBytes ?? DEFAULT_SBOM_WORKER_MINIMUM_BYTES;
  }
  async loadAllSboms(settings) {
    const enabledSboms = settings.sboms.filter((sbom) => sbom.enabled);
    const notePathResolver = this.createNotePathResolver();
    return Promise.all(enabledSboms.map((sbom) => this.loadSbom(sbom, { notePathResolver })));
  }
  async loadSbom(config, options) {
    const normalizedPath = this.normalizeSbomPath(config.path);
    const cached = this.runtimeCache.get(config.id) ?? null;
    if (!normalizedPath) {
      return {
        cachedState: cached,
        error: "SBOM path is required.",
        sbomId: config.id,
        success: false
      };
    }
    if (!options?.force && cached && cached.sourcePath === normalizedPath) {
      return {
        fromCache: true,
        sbomId: config.id,
        state: cached,
        success: true
      };
    }
    const loadToken = this.asyncTaskCoordinator.beginToken(this.getLoadTokenKey(config.id));
    try {
      const raw = await this.reader.read(normalizedPath);
      if (!this.asyncTaskCoordinator.isCurrent(loadToken)) {
        return this.buildStaleLoadResult(config.id, cached);
      }
      const parsed = await this.parseSbom(
        raw,
        normalizedPath,
        options?.notePathResolver ?? this.createNotePathResolver()
      );
      if (!this.asyncTaskCoordinator.isCurrent(loadToken)) {
        return this.buildStaleLoadResult(config.id, cached);
      }
      const state = {
        components: parsed.components,
        document: parsed.document,
        hash: await this.hashContent(raw),
        lastError: null,
        lastLoadedAt: Date.now(),
        sourcePath: normalizedPath
      };
      if (!this.asyncTaskCoordinator.isCurrent(loadToken)) {
        return this.buildStaleLoadResult(config.id, cached);
      }
      this.runtimeCache.set(config.id, state);
      return {
        fromCache: false,
        sbomId: config.id,
        state,
        success: true
      };
    } catch (error) {
      return {
        cachedState: cached,
        error: this.getErrorMessage(error),
        sbomId: config.id,
        success: false
      };
    } finally {
      this.asyncTaskCoordinator.releaseToken(loadToken);
    }
  }
  getRuntimeState(sbomId) {
    return this.runtimeCache.get(sbomId) ?? null;
  }
  getRuntimeCacheSnapshot() {
    return new Map(this.runtimeCache);
  }
  invalidateCache(sbomId) {
    this.runtimeCache.delete(sbomId);
  }
  invalidateAllCaches() {
    this.runtimeCache.clear();
  }
  async getFileChangeStatus(config) {
    const normalizedPath = this.normalizeSbomPath(config.path);
    if (!normalizedPath) {
      return {
        currentHash: null,
        error: "SBOM path is required.",
        status: "error"
      };
    }
    try {
      const exists = await this.reader.exists(normalizedPath);
      if (!exists) {
        return {
          currentHash: null,
          error: "SBOM file not found.",
          status: "missing"
        };
      }
      const raw = await this.reader.read(normalizedPath);
      const currentHash = await this.hashContent(raw);
      if (!config.contentHash) {
        return {
          currentHash,
          error: null,
          status: "not-imported"
        };
      }
      return {
        currentHash,
        error: null,
        status: currentHash === config.contentHash ? "unchanged" : "changed"
      };
    } catch (error) {
      return {
        currentHash: null,
        error: this.getErrorMessage(error),
        status: "error"
      };
    }
  }
  async validateSbomPath(path) {
    const normalizedPath = this.normalizeSbomPath(path);
    if (!normalizedPath) {
      return {
        error: "Choose a JSON SBOM file from your vault.",
        normalizedPath,
        success: false
      };
    }
    try {
      const exists = await this.reader.exists(normalizedPath);
      if (!exists) {
        return {
          error: "The selected SBOM file could not be found in the vault.",
          normalizedPath,
          success: false
        };
      }
      const raw = await this.reader.read(normalizedPath);
      const parsed = await this.parseSbom(raw, normalizedPath, null);
      return {
        componentCount: parsed.document.components.length,
        normalizedPath,
        success: true
      };
    } catch (error) {
      return {
        error: this.getErrorMessage(error),
        normalizedPath,
        success: false
      };
    }
  }
  async applyNotePaths(document, notePathResolver) {
    const components = await this.cooperativeScheduler.mapInBatches(document.components, (component) => {
      const noteInput = {
        name: component.name
      };
      if (component.cpe) {
        noteInput.cpe = component.cpe;
      }
      if (component.purl) {
        noteInput.purl = component.purl;
      }
      if (component.version) {
        noteInput.version = component.version;
      }
      const notePath = notePathResolver.resolve(noteInput);
      if (notePath === void 0) {
        return component;
      }
      return {
        ...component,
        notePath
      };
    }, {
      itemsPerYield: this.notePathItemsPerYield,
      timeoutMs: 16
    });
    return {
      ...document,
      components
    };
  }
  buildStaleLoadResult(sbomId, cachedState) {
    const current = this.runtimeCache.get(sbomId) ?? cachedState;
    if (current) {
      return {
        fromCache: true,
        sbomId,
        state: current,
        success: true
      };
    }
    return {
      cachedState: null,
      error: "A newer SBOM load completed first.",
      sbomId,
      success: false
    };
  }
  createNotePathResolver() {
    if (!this.notePathResolverFactory) {
      return null;
    }
    return this.notePathResolverFactory.createResolver();
  }
  async extractComponents(document) {
    const deduped = /* @__PURE__ */ new Map();
    let processedSinceYield = 0;
    for (const component of document.components) {
      const originalName = this.getString(component.name);
      if (!originalName) {
        continue;
      }
      const normalizedName = this.nameNormalizer.normalize(originalName);
      const effectiveName = normalizedName || originalName;
      const key = originalName.toLowerCase();
      if (!deduped.has(key)) {
        deduped.set(key, {
          normalizedName: effectiveName,
          originalName
        });
      }
      processedSinceYield += 1;
      if (processedSinceYield >= this.runtimeComponentItemsPerYield) {
        processedSinceYield = 0;
        await this.cooperativeScheduler.yieldToHost({ timeoutMs: 16 });
      }
    }
    return Array.from(deduped.values()).sort((left, right) => left.normalizedName.localeCompare(right.normalizedName) || left.originalName.localeCompare(right.originalName));
  }
  getLoadTokenKey(sbomId) {
    return `sbom-load:${sbomId}`;
  }
  async hashContent(content) {
    const buffer = new TextEncoder().encode(content);
    const digest = await crypto.subtle.digest("SHA-256", buffer);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
  }
  getBasename(path) {
    const segments = normalizePath(path).split("/").filter((segment) => segment.length > 0);
    const filename = segments.at(-1) ?? "sbom.json";
    const lastDotIndex = filename.lastIndexOf(".");
    return lastDotIndex > 0 ? filename.slice(0, lastDotIndex) : filename;
  }
  getErrorMessage(error) {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }
    return "Unable to load SBOM.";
  }
  getString(value) {
    return typeof value === "string" ? value.trim() : "";
  }
  normalizeSbomPath(path) {
    const trimmed = path.trim();
    return trimmed ? normalizePath(trimmed) : "";
  }
  async parseSbom(raw, sourcePath, notePathResolver) {
    const source = {
      basename: this.getBasename(sourcePath),
      path: sourcePath
    };
    const parseResult = await this.asyncTaskCoordinator.execute("parse-sbom", {
      raw,
      source
    }, {
      fallback: async ({ raw: fallbackRaw, source: fallbackSource }) => {
        const parsed = JSON.parse(fallbackRaw);
        if (!parsed || typeof parsed !== "object") {
          throw new Error("SBOM file is not a valid JSON object.");
        }
        return {
          document: parseSbomJson(parsed, { source: fallbackSource })
        };
      },
      preferWorker: raw.length >= this.workerMinimumBytes
    });
    const document = notePathResolver ? await this.applyNotePaths(parseResult.document, notePathResolver) : parseResult.document;
    return {
      components: await this.extractComponents(document),
      document
    };
  }
};

// src/application/ports/DataSourceError.ts
var HttpRequestError = class extends Error {
  constructor(name, message, retryable, metadata) {
    super(message);
    this.name = name;
    this.retryable = retryable;
    this.metadata = metadata;
  }
};
var RetryableNetworkError = class extends HttpRequestError {
  constructor(message, metadata) {
    super("RetryableNetworkError", message, true, metadata);
  }
};
var TimeoutHttpError = class extends HttpRequestError {
  constructor(message, metadata) {
    super("TimeoutHttpError", message, true, metadata);
  }
};
var RateLimitHttpError = class extends HttpRequestError {
  constructor(message, metadata) {
    super("RateLimitHttpError", message, true, metadata);
  }
};
var AuthFailureHttpError = class extends HttpRequestError {
  constructor(message, metadata) {
    super("AuthFailureHttpError", message, false, metadata);
  }
};
var ClientHttpError = class extends HttpRequestError {
  constructor(message, metadata) {
    super("ClientHttpError", message, false, metadata);
  }
};
var ServerHttpError = class extends HttpRequestError {
  constructor(message, metadata) {
    super("ServerHttpError", message, true, metadata);
  }
};

// src/application/pipeline/PipelineTypes.ts
var DEFAULT_PIPELINE_CONFIG = {
  chunkSize: 100,
  normalizeWorkerMinimumItems: 100
};
var buildVulnerabilityCacheKey = (vulnerability) => `${vulnerability.source}:${vulnerability.id}`;
var compareChangeKeys = (left, right) => left.localeCompare(right);
var compareVulnerabilitiesDeterministically = (left, right) => right.publishedAt.localeCompare(left.publishedAt) || right.updatedAt.localeCompare(left.updatedAt) || left.source.localeCompare(right.source) || left.id.localeCompare(right.id) || left.title.localeCompare(right.title);
var compareVulnerabilitiesByFreshness = (left, right) => left.updatedAt.localeCompare(right.updatedAt) || left.publishedAt.localeCompare(right.publishedAt) || left.source.localeCompare(right.source) || left.id.localeCompare(right.id) || left.title.localeCompare(right.title);
var sortVulnerabilitiesDeterministically = (vulnerabilities) => Array.from(vulnerabilities).sort(compareVulnerabilitiesDeterministically);
var toSortedChangedVulnerabilityIds = (values) => ({
  added: Array.from(values.added ?? []).sort(compareChangeKeys),
  removed: Array.from(values.removed ?? []).sort(compareChangeKeys),
  updated: Array.from(values.updated ?? []).sort(compareChangeKeys)
});

// src/domain/value-objects/CvssScore.ts
var classifySeverity = (score) => {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
};

// src/application/pipeline/VulnerabilityBatchNormalizer.ts
var compareNullableStrings = (left, right) => (left ?? "").localeCompare(right ?? "");
var uniqueSortedStrings = (values) => {
  if (!values || values.length === 0) {
    return [];
  }
  const uniqueValues = /* @__PURE__ */ new Map();
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) {
      continue;
    }
    const existing = uniqueValues.get(trimmed.toLowerCase());
    if (!existing || trimmed.localeCompare(existing) < 0) {
      uniqueValues.set(trimmed.toLowerCase(), trimmed);
    }
  }
  return Array.from(uniqueValues.values()).sort((left, right) => left.localeCompare(right));
};
var buildAffectedPackageKey = (pkg) => [
  pkg.cpe ?? "",
  pkg.ecosystem ?? "",
  pkg.firstPatchedVersion ?? "",
  pkg.name,
  pkg.purl ?? "",
  pkg.sourceCodeLocation ?? "",
  pkg.vendor ?? "",
  pkg.version ?? "",
  pkg.vulnerableVersionRange ?? "",
  ...pkg.vulnerableFunctions ?? []
].join("\0").toLowerCase();
var compareAffectedPackages = (left, right) => left.name.localeCompare(right.name) || compareNullableStrings(left.vendor, right.vendor) || compareNullableStrings(left.ecosystem, right.ecosystem) || compareNullableStrings(left.version, right.version) || compareNullableStrings(left.vulnerableVersionRange, right.vulnerableVersionRange) || compareNullableStrings(left.firstPatchedVersion, right.firstPatchedVersion) || compareNullableStrings(left.cpe, right.cpe) || compareNullableStrings(left.purl, right.purl) || compareNullableStrings(left.sourceCodeLocation, right.sourceCodeLocation);
var normalizeAffectedPackages = (packages) => {
  if (!packages || packages.length === 0) {
    return [];
  }
  const uniquePackages = /* @__PURE__ */ new Map();
  for (const pkg of packages) {
    const normalized = {
      ...pkg.cpe ? { cpe: pkg.cpe.trim() } : {},
      name: pkg.name.trim(),
      ...pkg.ecosystem ? { ecosystem: pkg.ecosystem.trim() } : {},
      ...pkg.firstPatchedVersion ? { firstPatchedVersion: pkg.firstPatchedVersion.trim() } : {},
      ...pkg.purl ? { purl: PurlNormalizer.normalize(pkg.purl) } : {},
      ...pkg.sourceCodeLocation ? { sourceCodeLocation: pkg.sourceCodeLocation.trim() } : {},
      ...pkg.vendor ? { vendor: pkg.vendor.trim() } : {},
      ...pkg.version ? { version: pkg.version.trim() } : {},
      ...pkg.vulnerableVersionRange ? { vulnerableVersionRange: pkg.vulnerableVersionRange.trim() } : {},
      ...pkg.vulnerableFunctions && pkg.vulnerableFunctions.length > 0 ? { vulnerableFunctions: uniqueSortedStrings(pkg.vulnerableFunctions) } : {}
    };
    if (!normalized.name) {
      continue;
    }
    uniquePackages.set(buildAffectedPackageKey(normalized), normalized);
  }
  return Array.from(uniquePackages.values()).sort(compareAffectedPackages);
};
var normalizeSourceUrls = (sourceUrls) => {
  if (!sourceUrls) {
    return void 0;
  }
  const normalized = {};
  if (sourceUrls.api?.trim()) {
    normalized.api = sourceUrls.api.trim();
  }
  if (sourceUrls.html?.trim()) {
    normalized.html = sourceUrls.html.trim();
  }
  if (sourceUrls.repositoryAdvisory?.trim()) {
    normalized.repositoryAdvisory = sourceUrls.repositoryAdvisory.trim();
  }
  if (sourceUrls.sourceCode?.trim()) {
    normalized.sourceCode = sourceUrls.sourceCode.trim();
  }
  return Object.keys(normalized).length > 0 ? normalized : void 0;
};
var normalizeMetadata = (metadata) => {
  if (!metadata) {
    return void 0;
  }
  const aliases = uniqueSortedStrings(metadata.aliases);
  const identifiers = uniqueSortedStrings(metadata.identifiers);
  const cwes = uniqueSortedStrings(metadata.cwes);
  const vendors = uniqueSortedStrings(metadata.vendors);
  const packages = uniqueSortedStrings(metadata.packages);
  const affectedPackages = normalizeAffectedPackages(metadata.affectedPackages);
  const vulnerableVersionRanges = uniqueSortedStrings(metadata.vulnerableVersionRanges);
  const firstPatchedVersions = uniqueSortedStrings(metadata.firstPatchedVersions);
  const vulnerableFunctions = uniqueSortedStrings(metadata.vulnerableFunctions);
  const sourceUrls = normalizeSourceUrls(metadata.sourceUrls);
  const normalized = {
    ...metadata.cveId?.trim() ? { cveId: metadata.cveId.trim() } : {},
    ...metadata.ghsaId?.trim() ? { ghsaId: metadata.ghsaId.trim() } : {},
    ...aliases.length > 0 ? { aliases } : {},
    ...identifiers.length > 0 ? { identifiers } : {},
    ...cwes.length > 0 ? { cwes } : {},
    ...vendors.length > 0 ? { vendors } : {},
    ...packages.length > 0 ? { packages } : {},
    ...affectedPackages.length > 0 ? { affectedPackages } : {},
    ...vulnerableVersionRanges.length > 0 ? { vulnerableVersionRanges } : {},
    ...firstPatchedVersions.length > 0 ? { firstPatchedVersions } : {},
    ...vulnerableFunctions.length > 0 ? { vulnerableFunctions } : {},
    ...sourceUrls ? { sourceUrls } : {}
  };
  return Object.keys(normalized).length > 0 ? normalized : void 0;
};
var normalizeVulnerabilityRecord = (vulnerability) => {
  const cvssScore = Number.isFinite(vulnerability.cvssScore) ? vulnerability.cvssScore : 0;
  const metadata = normalizeMetadata(vulnerability.metadata);
  return {
    ...vulnerability,
    affectedProducts: uniqueSortedStrings(vulnerability.affectedProducts),
    cvssScore,
    ...metadata ? { metadata } : {},
    references: uniqueSortedStrings(vulnerability.references),
    severity: classifySeverity(cvssScore)
  };
};
var normalizeVulnerabilityBatch = (input) => {
  const latestByKey = /* @__PURE__ */ new Map();
  for (const vulnerability of input.vulnerabilities) {
    const normalized = normalizeVulnerabilityRecord(vulnerability);
    const key = buildVulnerabilityCacheKey(normalized);
    const previous = latestByKey.get(key);
    if (!previous || compareVulnerabilitiesByFreshness(normalized, previous) > 0) {
      latestByKey.set(key, normalized);
    }
  }
  const vulnerabilities = sortVulnerabilitiesDeterministically(latestByKey.values());
  return {
    batchIndex: input.batchIndex,
    normalizedCount: vulnerabilities.length,
    sourceId: input.sourceId,
    sourceName: input.sourceName,
    totalFetchedItems: input.totalFetchedItems,
    vulnerabilities
  };
};

// src/application/pipeline/IngestionPipeline.ts
var sleep = async (ms) => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};
var IngestionPipeline = class {
  constructor(options = {}) {
    this.config = {
      ...DEFAULT_PIPELINE_CONFIG,
      ...options
    };
    this.asyncTaskCoordinator = options.asyncTaskCoordinator ?? new AsyncTaskCoordinator();
    this.cooperativeScheduler = options.cooperativeScheduler ?? new CooperativeScheduler();
  }
  async run(request) {
    const collected = await this.collectFetchBatches(request);
    const cacheByKey = new Map(request.snapshot.cacheByKey);
    const originByKey = new Map(request.snapshot.originByKey);
    const seenRun = /* @__PURE__ */ new Map();
    const aggregateAdded = /* @__PURE__ */ new Set();
    const aggregateUpdated = /* @__PURE__ */ new Set();
    const aggregateRemoved = /* @__PURE__ */ new Set();
    let itemsMerged = 0;
    let itemsDeduplicated = 0;
    let processedItems = 0;
    let batchIndex = 0;
    for (const fetchedBatch of collected.batches) {
      for (const chunk of this.createChunkInputs(
        fetchedBatch.vulnerabilities,
        collected.totalItems,
        request.source,
        batchIndex
      )) {
        batchIndex = chunk.batchIndex + 1;
        const normalizedBatch = await this.normalizeBatch(chunk);
        processedItems += normalizedBatch.normalizedCount;
        await request.onEvent?.({
          ...this.buildEventBase(request.source, normalizedBatch.batchIndex, processedItems, collected.totalItems),
          batch: normalizedBatch,
          input: chunk,
          stage: "transform"
        });
        const mergeResult = this.mergeNormalizedBatch(
          normalizedBatch,
          request.source,
          cacheByKey,
          originByKey,
          seenRun
        );
        itemsMerged += mergeResult.itemsMerged;
        itemsDeduplicated += mergeResult.itemsDeduplicated;
        this.mergeChangedIds(aggregateAdded, aggregateUpdated, aggregateRemoved, mergeResult.changedIds);
        await request.onEvent?.({
          ...this.buildEventBase(request.source, normalizedBatch.batchIndex, processedItems, collected.totalItems),
          mergeResult,
          stage: "merge"
        });
        if (mergeResult.changedIds.added.length > 0 || mergeResult.changedIds.updated.length > 0) {
          await request.onEvent?.({
            ...this.buildEventBase(request.source, normalizedBatch.batchIndex, processedItems, collected.totalItems),
            changedIds: mergeResult.changedIds,
            stage: "notify",
            vulnerabilities: sortVulnerabilitiesDeterministically(cacheByKey.values())
          });
        }
        await this.cooperativeScheduler.yieldToHost({ timeoutMs: 16 });
      }
    }
    const removedIds = this.removeMissingSnapshotItems(request.source, cacheByKey, originByKey, seenRun);
    if (removedIds.length > 0) {
      const changedIds = toSortedChangedVulnerabilityIds({ removed: removedIds });
      this.mergeChangedIds(aggregateAdded, aggregateUpdated, aggregateRemoved, changedIds);
      const mergeResult = {
        cacheSize: cacheByKey.size,
        changedIds,
        itemsDeduplicated: 0,
        itemsMerged: 0
      };
      await request.onEvent?.({
        ...this.buildEventBase(request.source, batchIndex, processedItems, collected.totalItems),
        mergeResult,
        stage: "merge"
      });
      await request.onEvent?.({
        ...this.buildEventBase(request.source, batchIndex, processedItems, collected.totalItems),
        changedIds,
        stage: "notify",
        vulnerabilities: sortVulnerabilitiesDeterministically(cacheByKey.values())
      });
    }
    return {
      cacheByKey,
      changedIds: toSortedChangedVulnerabilityIds({
        added: aggregateAdded,
        removed: aggregateRemoved,
        updated: aggregateUpdated
      }),
      itemsDeduplicated,
      itemsFetched: collected.totalItems,
      itemsMerged,
      originByKey,
      pagesFetched: collected.pagesFetched,
      retriesPerformed: collected.retriesPerformed,
      vulnerabilities: sortVulnerabilitiesDeterministically(cacheByKey.values()),
      warnings: collected.warnings
    };
  }
  async collectFetchBatches(request) {
    let delay = request.controls.backoffBaseMs;
    let retriesPerformed = 0;
    for (let attempt = 1; attempt <= request.controls.retryCount + 1; attempt += 1) {
      try {
        const batches = [];
        const warnings = [];
        let pagesFetched = 0;
        let totalItems = 0;
        for await (const batch of this.iterateFeedBatches(request.sourceFeed, request.source)) {
          batches.push(batch);
          pagesFetched += batch.pagesFetched ?? 0;
          totalItems += batch.vulnerabilities.length;
          warnings.push(...batch.warnings ?? []);
          await request.onEvent?.({
            ...this.buildEventBase(request.source, batches.length - 1, totalItems, totalItems),
            pagesFetched,
            retriesPerformed,
            stage: "fetch",
            warnings
          });
        }
        return {
          batches,
          pagesFetched,
          retriesPerformed,
          totalItems,
          warnings
        };
      } catch (error) {
        if (!this.isRetryable(error) || attempt > request.controls.retryCount) {
          throw error;
        }
        retriesPerformed += 1;
        const retryAfter = error instanceof RateLimitHttpError ? error.metadata.retryAfterMs : void 0;
        await sleep(retryAfter ?? delay);
        delay = Math.min(delay * 2, 3e4);
      }
    }
    return {
      batches: [],
      pagesFetched: 0,
      retriesPerformed,
      totalItems: 0,
      warnings: ["retry_budget_exhausted"]
    };
  }
  buildEventBase(source, batchIndex, processedItems, totalItems) {
    return {
      batchIndex,
      ...source.existingCursor ? { existingCursor: source.existingCursor } : {},
      processedItems,
      runId: source.runId,
      ...source.since ? { since: source.since } : {},
      sourceId: source.sourceId,
      sourceName: source.sourceName,
      totalItems,
      until: source.until
    };
  }
  createChunkInputs(vulnerabilities, totalFetchedItems, source, startingBatchIndex) {
    const batches = [];
    for (let index = 0; index < vulnerabilities.length; index += this.config.chunkSize) {
      batches.push({
        batchIndex: startingBatchIndex + batches.length,
        sourceId: source.sourceId,
        sourceName: source.sourceName,
        totalFetchedItems,
        vulnerabilities: vulnerabilities.slice(index, index + this.config.chunkSize)
      });
    }
    return batches;
  }
  async normalizeBatch(input) {
    const result = await this.asyncTaskCoordinator.execute("normalize-vulnerabilities", {
      input
    }, {
      fallback: async ({ input: fallbackInput }) => ({
        batch: normalizeVulnerabilityBatch(fallbackInput)
      }),
      preferWorker: input.vulnerabilities.length >= this.config.normalizeWorkerMinimumItems
    });
    return result.batch;
  }
  mergeNormalizedBatch(batch, source, cacheByKey, originByKey, seenRun) {
    const added = /* @__PURE__ */ new Set();
    const updated = /* @__PURE__ */ new Set();
    let itemsMerged = 0;
    let itemsDeduplicated = 0;
    for (const vulnerability of batch.vulnerabilities) {
      const key = buildVulnerabilityCacheKey(vulnerability);
      const previousRunItem = seenRun.get(key);
      if (previousRunItem) {
        itemsDeduplicated += 1;
        if (compareVulnerabilitiesByFreshness(vulnerability, previousRunItem) <= 0) {
          continue;
        }
      }
      seenRun.set(key, vulnerability);
      const existing = cacheByKey.get(key);
      if (!existing) {
        cacheByKey.set(key, vulnerability);
        originByKey.set(key, source.sourceId);
        added.add(key);
        itemsMerged += 1;
        continue;
      }
      if (compareVulnerabilitiesByFreshness(vulnerability, existing) > 0) {
        cacheByKey.set(key, vulnerability);
        originByKey.set(key, source.sourceId);
        updated.add(key);
        itemsMerged += 1;
      }
    }
    return {
      cacheSize: cacheByKey.size,
      changedIds: toSortedChangedVulnerabilityIds({ added, updated }),
      itemsDeduplicated,
      itemsMerged
    };
  }
  removeMissingSnapshotItems(source, cacheByKey, originByKey, seenRun) {
    if (source.syncMode !== "snapshot") {
      return [];
    }
    const removed = [];
    for (const [key, origin] of originByKey.entries()) {
      if (origin !== source.sourceId || seenRun.has(key)) {
        continue;
      }
      originByKey.delete(key);
      cacheByKey.delete(key);
      removed.push(key);
    }
    return removed.sort();
  }
  async *iterateFeedBatches(sourceFeed, source) {
    const options = {
      signal: new AbortController().signal,
      ...source.since ? { since: source.since } : {},
      until: source.until
    };
    if (sourceFeed.fetchVulnerabilityBatches) {
      yield* sourceFeed.fetchVulnerabilityBatches(options);
      return;
    }
    const result = await sourceFeed.fetchVulnerabilities(options);
    yield {
      pagesFetched: result.pagesFetched,
      retriesPerformed: result.retriesPerformed,
      vulnerabilities: result.vulnerabilities,
      warnings: result.warnings
    };
  }
  isRetryable(error) {
    return error instanceof RetryableNetworkError || error instanceof TimeoutHttpError || error instanceof RateLimitHttpError || error instanceof ServerHttpError || error instanceof HttpRequestError && error.retryable && !(error instanceof ClientHttpError) && !(error instanceof AuthFailureHttpError);
  }
  mergeChangedIds(aggregateAdded, aggregateUpdated, aggregateRemoved, changedIds) {
    for (const key of changedIds.added) {
      aggregateAdded.add(key);
      aggregateRemoved.delete(key);
    }
    for (const key of changedIds.updated) {
      if (!aggregateAdded.has(key)) {
        aggregateUpdated.add(key);
      }
    }
    for (const key of changedIds.removed) {
      aggregateAdded.delete(key);
      aggregateUpdated.delete(key);
      aggregateRemoved.add(key);
    }
  }
};

// src/application/pipeline/PipelineRunRegistry.ts
var PipelineRunRegistry = class {
  constructor() {
    this.activeRunIds = /* @__PURE__ */ new Map();
    this.generations = /* @__PURE__ */ new Map();
  }
  start(sourceId) {
    const nextGeneration = (this.generations.get(sourceId) ?? 0) + 1;
    this.generations.set(sourceId, nextGeneration);
    const runId = `${sourceId}:${nextGeneration}`;
    this.activeRunIds.set(sourceId, runId);
    return {
      generation: nextGeneration,
      runId,
      sourceId
    };
  }
  isCurrent(run) {
    return this.activeRunIds.get(run.sourceId) === run.runId;
  }
  finish(run) {
    if (this.activeRunIds.get(run.sourceId) === run.runId) {
      this.activeRunIds.delete(run.sourceId);
    }
  }
};

// src/application/use-cases/SyncVulnerabilitiesUseCase.ts
var VulnerabilitySyncService = class {
  constructor(options) {
    this.activeDrainPromise = null;
    this.cacheByKey = /* @__PURE__ */ new Map();
    this.originByKey = /* @__PURE__ */ new Map();
    this.pendingSyncRequested = false;
    this.runRegistry = new PipelineRunRegistry();
    this.controls = { ...options.controls };
    this.feeds = [...options.feeds];
    this.onPipelineEvent = options.onPipelineEvent;
    this.persistence = options.persistence ?? null;
    this.pipeline = new IngestionPipeline({
      ...DEFAULT_PIPELINE_CONFIG,
      ...options.pipelineConfig ?? {}
    });
    this.sourceSyncCursor = { ...options.state.sourceSyncCursor };
    for (const vulnerability of options.state.cache) {
      this.cacheByKey.set(`${vulnerability.source}:${vulnerability.id}`, vulnerability);
    }
  }
  updateConfiguration(feeds, controls) {
    this.feeds = [...feeds];
    this.controls = { ...controls };
  }
  async syncNow() {
    if (this.activeDrainPromise) {
      this.pendingSyncRequested = true;
      return this.activeDrainPromise;
    }
    this.activeDrainPromise = this.executeDrain();
    try {
      return await this.activeDrainPromise;
    } finally {
      this.activeDrainPromise = null;
    }
  }
  async executeDrain() {
    let latestOutcome = await this.executeOnce();
    while (this.pendingSyncRequested) {
      this.pendingSyncRequested = false;
      latestOutcome = await this.executeOnce();
    }
    return latestOutcome;
  }
  async executeOnce() {
    const results = [];
    for (const feed of this.feeds) {
      const result = await this.syncFeed(feed);
      results.push(result);
    }
    return {
      results,
      sourceSyncCursor: { ...this.sourceSyncCursor },
      vulnerabilities: await this.loadOutcomeVulnerabilities()
    };
  }
  async loadOutcomeVulnerabilities() {
    if (!this.persistence) {
      return sortVulnerabilitiesDeterministically(this.cacheByKey.values());
    }
    return this.persistence.cacheStore.loadLatest(
      this.persistence.cacheHydrationLimit,
      this.persistence.cacheHydrationPageSize
    );
  }
  async syncFeed(feed) {
    const startedAt = (/* @__PURE__ */ new Date()).toISOString();
    const warnings = [];
    const until = startedAt;
    const existingCursor = await this.getExistingCursor(feed.id);
    const since = existingCursor ? new Date(Date.parse(existingCursor) - this.controls.overlapWindowMs).toISOString() : new Date(Date.parse(until) - this.controls.bootstrapLookbackMs).toISOString();
    console.info("[vulndash.sync.start]", {
      bootstrapLookbackMs: this.controls.bootstrapLookbackMs,
      cursor: existingCursor,
      feedId: feed.id,
      overlapWindowMs: this.controls.overlapWindowMs,
      since,
      source: feed.name,
      until
    });
    const run = this.runRegistry.start(feed.id);
    try {
      if (this.persistence) {
        await this.persistence.metadataStore.recordAttempt(feed.id, startedAt);
      }
      const snapshot = this.persistence ? await this.persistence.cacheStore.loadSourceSnapshot(feed.id) : {
        cacheByKey: this.cacheByKey,
        originByKey: this.originByKey
      };
      const pipelineResult = await this.pipeline.run({
        controls: this.controls,
        ...this.onPipelineEvent ? {
          onEvent: async (event) => this.handlePipelineEventProxy(event)
        } : {},
        snapshot,
        source: {
          ...existingCursor ? { existingCursor } : {},
          runId: run.runId,
          since,
          sourceId: feed.id,
          sourceName: feed.name,
          syncMode: feed.syncMode ?? "incremental",
          until
        },
        sourceFeed: feed
      });
      if (!this.runRegistry.isCurrent(run)) {
        return {
          completedAt: (/* @__PURE__ */ new Date()).toISOString(),
          itemsDeduplicated: 0,
          itemsFetched: 0,
          itemsMerged: 0,
          pagesFetched: 0,
          retriesPerformed: 0,
          source: feed.name,
          startedAt,
          success: false,
          warnings: ["stale_pipeline_run"]
        };
      }
      await this.commitPipelineResult(feed.id, until, pipelineResult);
      warnings.push(...pipelineResult.warnings);
      console.info("[vulndash.sync.merge]", {
        deduplicated: pipelineResult.itemsDeduplicated,
        feedId: feed.id,
        fetched: pipelineResult.itemsFetched,
        merged: pipelineResult.itemsMerged,
        pagesFetched: pipelineResult.pagesFetched,
        source: feed.name,
        warnings: pipelineResult.warnings
      });
      console.info("[vulndash.sync.cursor.advance]", {
        feedId: feed.id,
        nextCursor: until,
        previousCursor: existingCursor,
        reason: "full_sync_success",
        source: feed.name
      });
      const successResult = {
        completedAt: (/* @__PURE__ */ new Date()).toISOString(),
        itemsDeduplicated: pipelineResult.itemsDeduplicated,
        itemsFetched: pipelineResult.itemsFetched,
        itemsMerged: pipelineResult.itemsMerged,
        pagesFetched: pipelineResult.pagesFetched,
        retriesPerformed: pipelineResult.retriesPerformed,
        source: feed.name,
        startedAt,
        success: true,
        warnings
      };
      console.info("[vulndash.sync.success]", successResult);
      return successResult;
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown sync error";
      const failureResult = {
        completedAt: (/* @__PURE__ */ new Date()).toISOString(),
        itemsDeduplicated: 0,
        itemsFetched: 0,
        itemsMerged: 0,
        pagesFetched: 0,
        retriesPerformed: 0,
        source: feed.name,
        startedAt,
        success: false,
        warnings,
        errorSummary: message
      };
      console.info("[vulndash.sync.cursor.skip]", {
        cursorRetained: existingCursor,
        feedId: feed.id,
        reason: "sync_failed",
        source: feed.name
      });
      console.warn("[vulndash.sync.failure]", failureResult);
      return failureResult;
    } finally {
      this.runRegistry.finish(run);
    }
  }
  async commitPipelineResult(feedId, until, pipelineResult) {
    if (this.persistence) {
      await this.persistence.cacheStore.replaceSourceSnapshot(feedId, pipelineResult.vulnerabilities, until);
      await this.persistence.metadataStore.recordSuccess(feedId, until, until);
    } else {
      this.cacheByKey = pipelineResult.cacheByKey;
      this.originByKey = pipelineResult.originByKey;
    }
    this.sourceSyncCursor[feedId] = until;
  }
  async getExistingCursor(feedId) {
    if (!this.persistence) {
      return this.sourceSyncCursor[feedId];
    }
    const existingCursor = await this.persistence.metadataStore.getLastSuccessfulSyncAt(feedId) ?? this.sourceSyncCursor[feedId];
    if (existingCursor) {
      this.sourceSyncCursor[feedId] = existingCursor;
    }
    return existingCursor;
  }
  async handlePipelineEventProxy(event) {
    if (!this.onPipelineEvent) {
      return;
    }
    if (this.persistence && event.stage === "notify") {
      return;
    }
    await this.onPipelineEvent(event);
  }
};

// src/infrastructure/correlation/SbomComponentIndex.ts
var normalizeComponentKey2 = (value) => value.trim().toLowerCase();
var SbomComponentIndex = class {
  build(components, sbomIdsBySourcePath) {
    const sbomIdsByComponentKey = /* @__PURE__ */ new Map();
    for (const component of components) {
      const matchedSbomIds = /* @__PURE__ */ new Set();
      for (const source of component.sources) {
        const sourceSbomIds = sbomIdsBySourcePath.get(source.sourcePath) ?? [];
        for (const sbomId of sourceSbomIds) {
          matchedSbomIds.add(sbomId);
        }
      }
      const normalizedComponentKey = normalizeComponentKey2(component.key);
      sbomIdsByComponentKey.set(
        normalizedComponentKey,
        Array.from(matchedSbomIds).sort((left, right) => left.localeCompare(right))
      );
    }
    return new BuiltSbomComponentIndex(sbomIdsByComponentKey);
  }
};
var BuiltSbomComponentIndex = class {
  constructor(sbomIdsByComponentKey) {
    this.sbomIdsByComponentKey = sbomIdsByComponentKey;
  }
  getSbomIdsForComponent(componentKey) {
    return this.sbomIdsByComponentKey.get(normalizeComponentKey2(componentKey)) ?? [];
  }
};

// src/application/dashboard/PublishedDateWindow.ts
var DAY_IN_MS = 24 * 60 * 60 * 1e3;
var filterVulnerabilitiesByDateWindow = (vulnerabilities, window, field) => {
  const fromMs = Date.parse(window.from);
  const toMs = Date.parse(window.to);
  if (Number.isNaN(fromMs) || Number.isNaN(toMs)) {
    return [...vulnerabilities];
  }
  return vulnerabilities.filter((vulnerability) => {
    const timestamp = field === "modified" ? vulnerability.updatedAt : vulnerability.publishedAt;
    const timestampMs = Date.parse(timestamp);
    return !Number.isNaN(timestampMs) && timestampMs >= fromMs && timestampMs <= toMs;
  });
};

// src/infrastructure/security/sanitize.ts
var sanitizeText = (value) => value.replace(/[\u0000-\u001F\u007F]/g, " ").replace(/\s+/g, " ").trim();
var sanitizeMarkdown = (value) => value.replace(/\r\n/g, "\n").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim();
var sanitizeUrl = (url) => {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "";
    }
    return parsed.toString();
  } catch {
    return "";
  }
};

// src/infrastructure/clients/common/ClientLogger.ts
var NoopClientLogger = class {
  onRequestStart(_context) {
  }
  onRequestSuccess(_context) {
  }
  onRequestRetry(_context) {
  }
  onRequestFailure(_context) {
  }
};

// src/infrastructure/clients/common/HeaderSanitizer.ts
var REDACTED_VALUE = "[REDACTED]";
var SENSITIVE_HEADERS = /* @__PURE__ */ new Set([
  "authorization",
  "proxy-authorization",
  "apikey",
  "api-key",
  "x-api-key",
  "cookie",
  "set-cookie"
]);
var sanitizeHeadersForLogs = (headers) => {
  const sanitized = {};
  for (const [key, value] of Object.entries(headers)) {
    sanitized[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? REDACTED_VALUE : value;
  }
  return sanitized;
};

// src/infrastructure/clients/common/RetryPolicy.ts
var DEFAULT_RETRY_POLICY = {
  maxAttempts: 3,
  baseDelayMs: 1e3,
  maxDelayMs: 3e4,
  jitter: true
};
var normalizeRetryPolicy = (policy = {}) => ({
  maxAttempts: Math.max(1, Math.trunc(policy.maxAttempts ?? DEFAULT_RETRY_POLICY.maxAttempts)),
  baseDelayMs: Math.max(1, Math.trunc(policy.baseDelayMs ?? DEFAULT_RETRY_POLICY.baseDelayMs)),
  maxDelayMs: Math.max(1, Math.trunc(policy.maxDelayMs ?? DEFAULT_RETRY_POLICY.maxDelayMs)),
  jitter: policy.jitter ?? DEFAULT_RETRY_POLICY.jitter
});

// src/infrastructure/clients/common/RetryExecutor.ts
var sleep2 = async (delayMs) => {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
};
var isRetryableHttpRequestError = (error) => error instanceof HttpRequestError && error.retryable;
var RetryExecutor = class {
  constructor(policy, logger, dependencies = {}) {
    this.logger = logger;
    this.policy = normalizeRetryPolicy(policy);
    this.random = dependencies.random ?? Math.random;
    this.sleep = dependencies.sleep ?? sleep2;
  }
  async execute(action, baseContext) {
    for (let attempt = 1; attempt <= this.policy.maxAttempts; attempt += 1) {
      try {
        return await action(attempt);
      } catch (error) {
        if (!isRetryableHttpRequestError(error) || attempt >= this.policy.maxAttempts) {
          this.logger.onRequestFailure(this.buildContext(baseContext, attempt, error));
          throw error;
        }
        const delayMs = this.computeRetryDelayMs(attempt, error.metadata.retryAfterMs);
        this.logger.onRequestRetry(this.buildContext(baseContext, attempt, error, delayMs));
        await this.sleep(delayMs);
      }
    }
    throw new Error("RetryExecutor exhausted attempts without returning a result.");
  }
  computeRetryDelayMs(attempt, retryAfterMs) {
    if (typeof retryAfterMs === "number" && Number.isFinite(retryAfterMs)) {
      return Math.max(0, Math.trunc(retryAfterMs));
    }
    const boundedDelay = Math.min(
      this.policy.baseDelayMs * 2 ** Math.max(0, attempt - 1),
      this.policy.maxDelayMs
    );
    if (!this.policy.jitter) {
      return boundedDelay;
    }
    const jitterMultiplier = 0.5 + this.random();
    return Math.min(
      this.policy.maxDelayMs,
      Math.max(0, Math.round(boundedDelay * jitterMultiplier))
    );
  }
  buildContext(baseContext, attempt, error, retryDelayMs) {
    const errorName = error instanceof Error ? error.name : "UnknownError";
    const status = error instanceof HttpRequestError ? error.metadata.status : void 0;
    return {
      ...baseContext,
      attempt,
      ...status !== void 0 ? { status } : {},
      ...retryDelayMs !== void 0 ? { retryDelayMs } : {},
      errorName
    };
  }
};

// src/infrastructure/clients/common/ClientBase.ts
var DEFAULT_CLIENT_LOGGER = new NoopClientLogger();
var createRetryPolicyFromControls = (controls) => normalizeRetryPolicy({
  maxAttempts: Math.max(1, (controls?.retryCount ?? 0) + 1),
  baseDelayMs: controls?.backoffBaseMs ?? DEFAULT_RETRY_POLICY.baseDelayMs,
  maxDelayMs: DEFAULT_RETRY_POLICY.maxDelayMs,
  jitter: DEFAULT_RETRY_POLICY.jitter
});
var ClientBase = class {
  constructor(httpClient, providerOrLogger, controlsOrRetryPolicy, logger, retryPolicy) {
    this.httpClient = httpClient;
    if (typeof providerOrLogger === "string") {
      this.defaultProvider = providerOrLogger;
      this.logger = logger ?? DEFAULT_CLIENT_LOGGER;
      this.retryExecutor = new RetryExecutor(
        retryPolicy ? normalizeRetryPolicy(retryPolicy) : createRetryPolicyFromControls(controlsOrRetryPolicy),
        this.logger
      );
      return;
    }
    this.defaultProvider = void 0;
    this.logger = providerOrLogger ?? DEFAULT_CLIENT_LOGGER;
    this.retryExecutor = new RetryExecutor(
      normalizeRetryPolicy(controlsOrRetryPolicy ?? DEFAULT_RETRY_POLICY),
      this.logger
    );
  }
  async getJsonWithResilience(request) {
    return this.executeJsonRequest({
      method: "GET",
      context: request.context,
      url: request.context.url,
      headers: request.headers,
      signal: request.signal,
      ...request.decorateError ? { decorateError: request.decorateError } : {}
    });
  }
  async postJsonWithResilience(request) {
    return this.executeJsonRequest({
      method: "POST",
      body: request.body,
      context: request.context,
      url: request.context.url,
      headers: request.headers,
      signal: request.signal,
      ...request.decorateError ? { decorateError: request.decorateError } : {}
    });
  }
  async executeGetJson(request) {
    return this.getJsonWithResilience({
      context: {
        provider: this.defaultProvider ?? "unknown",
        operation: request.operationName,
        url: request.url
      },
      headers: request.headers,
      signal: request.signal,
      ...request.decorateError ? { decorateError: request.decorateError } : {}
    });
  }
  async executeJsonRequest(request) {
    const sanitizedHeaders = sanitizeHeadersForLogs(request.headers);
    const baseContext = {
      provider: request.context.provider,
      operation: request.context.operation,
      url: request.url,
      headers: sanitizedHeaders
    };
    let lastAttempt = 1;
    const response = await this.retryExecutor.execute(async (attempt) => {
      lastAttempt = attempt;
      const attemptContext = {
        ...baseContext,
        attempt
      };
      this.logger.onRequestStart(attemptContext);
      try {
        const result = request.method === "POST" ? await this.executePostJson(request) : await this.httpClient.getJson(request.url, request.headers, request.signal);
        this.logger.onRequestSuccess({
          ...attemptContext,
          status: result.status
        });
        return result;
      } catch (error) {
        throw request.decorateError ? request.decorateError(error) : error;
      }
    }, baseContext);
    return {
      response,
      retriesPerformed: Math.max(0, lastAttempt - 1)
    };
  }
  async executePostJson(request) {
    if (!this.httpClient.postJson) {
      throw new Error("HTTP client does not support JSON POST requests.");
    }
    return this.httpClient.postJson(
      request.url,
      request.body,
      request.headers,
      request.signal
    );
  }
};

// src/infrastructure/clients/github/GitHubAdvisoryClient.ts
var GITHUB_ADVISORIES_ENDPOINT = "https://api.github.com/advisories";
var GITHUB_API_VERSION = "2022-11-28";
var severityToScore = (severity) => {
  switch (severity) {
    case "critical":
      return 9.5;
    case "high":
      return 8;
    case "moderate":
      return 5.5;
    case "low":
      return 2.5;
    default:
      return 0;
  }
};
var uniqueNonEmpty = (values) => {
  const seen = /* @__PURE__ */ new Set();
  const result = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(trimmed);
  }
  return result;
};
var findIdentifier = (identifiers, prefix) => identifiers.find((identifier) => identifier.toLowerCase().startsWith(prefix.toLowerCase()));
var deriveVendor = (packageName, sourceCodeLocation) => {
  const scopeMatch = packageName.match(/^@([^/]+)\//);
  if (scopeMatch?.[1]) {
    return scopeMatch[1];
  }
  const githubMatch = sourceCodeLocation.match(/^https?:\/\/(?:www\.)?github\.com\/([^/\s]+)/i);
  return githubMatch?.[1] ?? "";
};
var extractNextLink = (linkHeader) => {
  if (!linkHeader) return void 0;
  const segments = linkHeader.split(",");
  for (const segment of segments) {
    const match = segment.match(/<([^>]+)>\s*;\s*rel="([^"]+)"/);
    if (match?.[2] === "next") {
      return match[1];
    }
  }
  return void 0;
};
var GitHubAdvisoryClient = class extends ClientBase {
  constructor(httpClient, id, name, token, controls) {
    super(httpClient, name, controls);
    this.id = id;
    this.name = name;
    this.token = token;
    this.controls = controls;
  }
  async fetchVulnerabilities(options) {
    const headers = {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": GITHUB_API_VERSION,
      "User-Agent": "obsidian-vulndash"
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const warnings = [];
    const dedup = /* @__PURE__ */ new Set();
    const collected = [];
    const seenUrls = /* @__PURE__ */ new Set();
    let pagesFetched = 0;
    let retriesPerformed = 0;
    let nextUrl = this.buildInitialUrl(options.since);
    while (nextUrl && pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenUrls.has(nextUrl)) {
        warnings.push("duplicate_next_url");
        break;
      }
      seenUrls.add(nextUrl);
      const { response, retriesPerformed: requestRetries } = await this.executeGetJson({
        operationName: "fetchVulnerabilities",
        url: nextUrl,
        headers,
        signal: options.signal,
        decorateError: (error) => this.decorateGitHubError(error)
      });
      retriesPerformed += requestRetries;
      pagesFetched += 1;
      const advisories = Array.isArray(response.data) ? response.data : response.data.items ?? [];
      let newItems = 0;
      for (const advisory of advisories) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push("max_items_reached");
          break;
        }
        const normalized = this.normalize(advisory, this.name);
        const filteredBatch = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil ? filterVulnerabilitiesByDateWindow([normalized], {
          from: options.modifiedFrom ?? options.publishedFrom ?? (/* @__PURE__ */ new Date(0)).toISOString(),
          to: options.modifiedUntil ?? options.publishedUntil ?? (/* @__PURE__ */ new Date(864e13)).toISOString()
        }, options.modifiedFrom || options.modifiedUntil ? "modified" : "published") : [normalized];
        const filteredItem = filteredBatch[0];
        if (!filteredItem) {
          continue;
        }
        const key = `${filteredItem.source}:${filteredItem.id}`;
        if (dedup.has(key)) continue;
        dedup.add(key);
        collected.push(filteredItem);
        newItems += 1;
      }
      if (newItems === 0) {
        warnings.push("no_new_unique_records");
        console.info("[vulndash.github.fetch.page]", {
          source: this.name,
          feedId: this.id,
          page: pagesFetched,
          status: response.status,
          itemCount: advisories.length,
          newUniqueItems: newItems,
          warning: "no_new_unique_records",
          nextPage: extractNextLink(response.headers.link)
        });
        nextUrl = extractNextLink(response.headers.link);
        continue;
      }
      console.info("[vulndash.github.fetch.page]", {
        source: this.name,
        feedId: this.id,
        page: pagesFetched,
        status: response.status,
        itemCount: advisories.length,
        newUniqueItems: newItems,
        nextPage: extractNextLink(response.headers.link)
      });
      nextUrl = extractNextLink(response.headers.link);
    }
    if (pagesFetched >= this.controls.maxPages) warnings.push("max_pages_reached");
    console.info("[vulndash.github.fetch.complete]", {
      source: this.name,
      feedId: this.id,
      pagesFetched,
      itemsFetched: collected.length,
      warnings,
      retriesPerformed
    });
    return {
      vulnerabilities: collected,
      pagesFetched,
      warnings,
      retriesPerformed
    };
  }
  buildInitialUrl(since) {
    const params = new URLSearchParams({ per_page: "100" });
    if (since) params.set("since", since);
    return `${GITHUB_ADVISORIES_ENDPOINT}?${params.toString()}`;
  }
  decorateGitHubError(error) {
    if (!(error instanceof ClientHttpError)) return error;
    if (error.metadata.status === 401) {
      return new AuthFailureHttpError(
        "GitHub advisories request unauthorized (401). Check token validity for the configured GitHub feed.",
        error.metadata
      );
    }
    if (error.metadata.status === 403) {
      const hasToken = Boolean(this.token);
      return new AuthFailureHttpError(
        hasToken ? "GitHub advisories request forbidden (403). Token may be missing required advisory access permissions or may be rate-limited." : "GitHub advisories request forbidden (403). Configure a GitHub token to avoid low anonymous rate limits.",
        error.metadata
      );
    }
    return error;
  }
  normalize(advisory, sourceLabel) {
    const score = advisory.cvss?.score ?? severityToScore(advisory.severity);
    const summary = advisory.description ?? advisory.summary ?? "No summary provided";
    const publishedAt = advisory.published_at ?? (/* @__PURE__ */ new Date(0)).toISOString();
    const updatedAt = advisory.updated_at ?? publishedAt;
    const identifiers = uniqueNonEmpty((advisory.identifiers ?? []).map((identifier) => sanitizeText(identifier.value ?? "")));
    const ghsaId = sanitizeText(advisory.ghsa_id ?? findIdentifier(identifiers, "GHSA-") ?? "");
    const cveId = sanitizeText(advisory.cve_id ?? findIdentifier(identifiers, "CVE-") ?? "");
    const cwes = uniqueNonEmpty((advisory.cwes ?? []).map((cwe) => sanitizeText(cwe.cwe_id ?? "")).filter((cwe) => /^CWE-\d+$/i.test(cwe)));
    const affectedPackages = (advisory.vulnerabilities ?? []).map((vulnerability) => {
      const packageName = sanitizeText(vulnerability.package?.name ?? "");
      if (!packageName) {
        return null;
      }
      const ecosystem = sanitizeText(vulnerability.package?.ecosystem ?? "");
      const sourceCodeLocation = sanitizeUrl(vulnerability.source_code_location ?? advisory.source_code_location ?? "");
      const vulnerableVersionRange = sanitizeText(vulnerability.vulnerable_version_range ?? "");
      const firstPatchedVersion = sanitizeText(vulnerability.first_patched_version?.identifier ?? "");
      const vulnerableFunctions2 = uniqueNonEmpty((vulnerability.vulnerable_functions ?? []).map((vulnerableFunction) => sanitizeText(vulnerableFunction)));
      const vendor = sanitizeText(deriveVendor(packageName, sourceCodeLocation));
      return {
        name: packageName,
        ...ecosystem ? { ecosystem } : {},
        ...vendor ? { vendor } : {},
        ...sourceCodeLocation ? { sourceCodeLocation } : {},
        ...vulnerableVersionRange ? { vulnerableVersionRange } : {},
        ...firstPatchedVersion ? { firstPatchedVersion } : {},
        ...vulnerableFunctions2.length > 0 ? { vulnerableFunctions: vulnerableFunctions2 } : {}
      };
    }).filter((vulnerability) => vulnerability !== null);
    const packages = uniqueNonEmpty(affectedPackages.map((vulnerability) => vulnerability.name));
    const vendors = uniqueNonEmpty(affectedPackages.map((vulnerability) => vulnerability.vendor ?? ""));
    const vulnerableVersionRanges = uniqueNonEmpty(affectedPackages.map((vulnerability) => vulnerability.vulnerableVersionRange ? `${vulnerability.name}: ${vulnerability.vulnerableVersionRange}` : ""));
    const firstPatchedVersions = uniqueNonEmpty(affectedPackages.map((vulnerability) => vulnerability.firstPatchedVersion ? `${vulnerability.name}: ${vulnerability.firstPatchedVersion}` : ""));
    const vulnerableFunctions = uniqueNonEmpty(affectedPackages.flatMap((vulnerability) => vulnerability.vulnerableFunctions ?? []));
    const sourceUrls = {};
    const apiUrl = sanitizeUrl(advisory.url ?? "");
    const htmlUrl = sanitizeUrl(advisory.html_url ?? "");
    const repositoryAdvisoryUrl = sanitizeUrl(advisory.repository_advisory_url ?? "");
    const sourceCodeUrl = sanitizeUrl(advisory.source_code_location ?? "");
    if (apiUrl) sourceUrls.api = apiUrl;
    if (htmlUrl) sourceUrls.html = htmlUrl;
    if (repositoryAdvisoryUrl) sourceUrls.repositoryAdvisory = repositoryAdvisoryUrl;
    if (sourceCodeUrl) sourceUrls.sourceCode = sourceCodeUrl;
    const metadata = {};
    if (cveId) metadata.cveId = cveId;
    if (ghsaId) metadata.ghsaId = ghsaId;
    if (identifiers.length > 0) metadata.identifiers = identifiers;
    const aliases = uniqueNonEmpty(identifiers.filter((identifier) => identifier !== ghsaId && identifier !== cveId));
    if (aliases.length > 0) metadata.aliases = aliases;
    if (cwes.length > 0) metadata.cwes = cwes;
    if (vendors.length > 0) metadata.vendors = vendors;
    if (packages.length > 0) metadata.packages = packages;
    if (affectedPackages.length > 0) metadata.affectedPackages = affectedPackages;
    if (vulnerableVersionRanges.length > 0) metadata.vulnerableVersionRanges = vulnerableVersionRanges;
    if (firstPatchedVersions.length > 0) metadata.firstPatchedVersions = firstPatchedVersions;
    if (vulnerableFunctions.length > 0) metadata.vulnerableFunctions = vulnerableFunctions;
    if (Object.keys(sourceUrls).length > 0) metadata.sourceUrls = sourceUrls;
    const references = uniqueNonEmpty([
      htmlUrl,
      repositoryAdvisoryUrl,
      sourceCodeUrl,
      ...(advisory.references ?? []).map((reference) => sanitizeUrl(reference))
    ]);
    return {
      id: ghsaId || cveId || "unknown",
      source: sourceLabel,
      title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? "GitHub Advisory"),
      summary: sanitizeMarkdown(summary),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references,
      affectedProducts: packages,
      ...Object.keys(metadata).length > 0 ? { metadata } : {}
    };
  }
};

// src/infrastructure/clients/github/GitHubRepoClient.ts
var normalizeRepoPath = (repoPath) => repoPath.trim().toLowerCase();
var severityToScore2 = (severity) => {
  switch (severity) {
    case "critical":
      return 9.5;
    case "high":
      return 8;
    case "moderate":
      return 5.5;
    case "low":
      return 2.5;
    default:
      return 0;
  }
};
var uniqueNonEmpty2 = (values) => {
  const seen = /* @__PURE__ */ new Set();
  const result = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(trimmed);
  }
  return result;
};
var GitHubRepoClient = class extends ClientBase {
  constructor(httpClient, id, name, token, repoPath, controls) {
    super(httpClient, name, controls);
    this.id = id;
    this.name = name;
    this.token = token;
    this.controls = controls;
    this.normalizedRepoPath = normalizeRepoPath(repoPath);
  }
  async fetchVulnerabilities(options) {
    const headers = {
      Accept: "application/vnd.github+json"
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    const warnings = [];
    const dedup = /* @__PURE__ */ new Set();
    const collected = [];
    const seenUrls = /* @__PURE__ */ new Set();
    let pagesFetched = 0;
    let retriesPerformed = 0;
    const params = new URLSearchParams({ per_page: "100", affects: this.normalizedRepoPath });
    if (options.since) params.set("updated", options.since);
    let nextUrl = `https://api.github.com/advisories?${params.toString()}`;
    while (nextUrl && pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenUrls.has(nextUrl)) {
        warnings.push("duplicate_next_url");
        break;
      }
      seenUrls.add(nextUrl);
      const { response, retriesPerformed: requestRetries } = await this.executeGetJson({
        operationName: "fetchVulnerabilities",
        url: nextUrl,
        headers,
        signal: options.signal
      });
      retriesPerformed += requestRetries;
      pagesFetched += 1;
      const advisories = Array.isArray(response.data) ? response.data : response.data.items ?? [];
      let newItems = 0;
      for (const advisory of advisories) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push("max_items_reached");
          break;
        }
        const normalized = this.normalize(advisory);
        const filteredBatch = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil ? filterVulnerabilitiesByDateWindow([normalized], {
          from: options.modifiedFrom ?? options.publishedFrom ?? (/* @__PURE__ */ new Date(0)).toISOString(),
          to: options.modifiedUntil ?? options.publishedUntil ?? (/* @__PURE__ */ new Date(864e13)).toISOString()
        }, options.modifiedFrom || options.modifiedUntil ? "modified" : "published") : [normalized];
        const filteredItem = filteredBatch[0];
        if (!filteredItem) {
          continue;
        }
        const key = `${filteredItem.source}:${filteredItem.id}`;
        if (dedup.has(key)) continue;
        dedup.add(key);
        collected.push(filteredItem);
        newItems += 1;
      }
      if (newItems === 0) {
        warnings.push("no_new_unique_records");
        break;
      }
      nextUrl = extractNextLink(response.headers.link);
    }
    if (pagesFetched >= this.controls.maxPages) warnings.push("max_pages_reached");
    return {
      vulnerabilities: collected,
      pagesFetched,
      warnings,
      retriesPerformed
    };
  }
  normalize(advisory) {
    const score = advisory.cvss?.score ?? severityToScore2(advisory.severity);
    const summary = advisory.description ?? advisory.summary ?? "No summary provided";
    const publishedAt = advisory.published_at ?? (/* @__PURE__ */ new Date(0)).toISOString();
    const updatedAt = advisory.updated_at ?? publishedAt;
    const source = `GitHub:${this.normalizedRepoPath}`;
    return {
      id: sanitizeText(advisory.ghsa_id ?? "unknown"),
      source,
      title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? "GitHub Advisory"),
      summary: sanitizeMarkdown(summary),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: [sanitizeUrl(advisory.html_url ?? "")].filter(Boolean),
      affectedProducts: uniqueNonEmpty2((advisory.vulnerabilities ?? []).map((v) => sanitizeText(v.package?.name ?? "")))
    };
  }
};

// src/infrastructure/clients/generic/GenericJsonFeedClient.ts
var severityToScore3 = (severity) => {
  switch (severity) {
    case "critical":
      return 9.5;
    case "high":
      return 8;
    case "medium":
      return 5;
    case "low":
      return 2.5;
    default:
      return 0;
  }
};
var GenericJsonFeedClient = class extends ClientBase {
  constructor(httpClient, id, name, url, token, authHeaderName, controls) {
    super(httpClient, name, controls);
    this.id = id;
    this.name = name;
    this.url = url;
    this.token = token;
    this.authHeaderName = authHeaderName;
    this.controls = controls;
  }
  async fetchVulnerabilities(options) {
    const warnings = [];
    const headers = {};
    if (this.token) {
      headers[this.authHeaderName] = this.token;
    }
    const { response, retriesPerformed } = await this.executeGetJson({
      operationName: "fetchVulnerabilities",
      url: this.url,
      headers,
      signal: options.signal
    });
    const records = response.data.vulnerabilities ?? [];
    const vulnerabilities = records.slice(0, this.controls.maxItems).map((record) => this.normalize(record));
    const filteredVulnerabilities = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil ? filterVulnerabilitiesByDateWindow(vulnerabilities, {
      from: options.modifiedFrom ?? options.publishedFrom ?? (/* @__PURE__ */ new Date(0)).toISOString(),
      to: options.modifiedUntil ?? options.publishedUntil ?? (/* @__PURE__ */ new Date(864e13)).toISOString()
    }, options.modifiedFrom || options.modifiedUntil ? "modified" : "published") : vulnerabilities;
    if (records.length > this.controls.maxItems) {
      warnings.push("max_items_reached");
    }
    return {
      vulnerabilities: filteredVulnerabilities,
      pagesFetched: 1,
      warnings,
      retriesPerformed
    };
  }
  normalize(record) {
    const score = typeof record.cvssScore === "number" ? record.cvssScore : severityToScore3(record.severity);
    const source = sanitizeText(record.source ?? `Generic:${this.name}`);
    const publishedAt = sanitizeText(record.publishedAt ?? (/* @__PURE__ */ new Date(0)).toISOString());
    const updatedAt = sanitizeText(record.updatedAt ?? publishedAt);
    return {
      id: sanitizeText(record.id ?? "unknown"),
      source,
      title: sanitizeText(record.title ?? record.id ?? this.name),
      summary: sanitizeMarkdown(record.summary ?? "No summary provided"),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: (record.references ?? []).map((reference) => sanitizeUrl(reference)).filter(Boolean),
      affectedProducts: (record.affectedProducts ?? []).map((product) => sanitizeText(product)).filter(Boolean)
    };
  }
};

// src/infrastructure/clients/nvd/NvdMapper.ts
var uniqueNonEmpty3 = (values) => {
  const seen = /* @__PURE__ */ new Set();
  const result = [];
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(trimmed);
  }
  return result;
};
var cleanCpeToken = (token) => {
  if (!token || token === "*" || token === "-") {
    return "";
  }
  return token.replace(/\\([\\:*?!])/g, "$1").replace(/_/g, " ").trim();
};
var buildVersionRange = (match, version) => {
  const parts = [
    version,
    match.versionStartIncluding ? `>= ${match.versionStartIncluding}` : "",
    match.versionStartExcluding ? `> ${match.versionStartExcluding}` : "",
    match.versionEndIncluding ? `<= ${match.versionEndIncluding}` : "",
    match.versionEndExcluding ? `< ${match.versionEndExcluding}` : ""
  ].filter(Boolean);
  return parts.join(", ");
};
var toSentenceTitle = (description, cveId) => {
  const normalized = sanitizeText(description);
  if (!normalized || normalized === "No summary provided") {
    return cveId || "Unknown CVE";
  }
  const firstSentence = normalized.split(/(?<=[.!?])\s+/)[0] ?? normalized;
  const titleSource = firstSentence.length >= 24 ? firstSentence : normalized;
  if (titleSource.length <= 120) {
    return titleSource;
  }
  const truncated = titleSource.slice(0, 117);
  const lastSpace = truncated.lastIndexOf(" ");
  const safeBoundary = lastSpace >= 60 ? lastSpace : truncated.length;
  return `${truncated.slice(0, safeBoundary).trimEnd()}...`;
};
var NvdMapper = class {
  constructor(sourceName) {
    this.sourceName = sourceName;
    this.productNameNormalizer = new ProductNameNormalizer();
  }
  normalize(cve) {
    const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ?? cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? 0;
    const description = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "No summary provided";
    const refs = (cve.references ?? []).map((r) => sanitizeUrl(r.url ?? "")).filter(Boolean);
    const cpeMatches = this.collectCpeMatches(cve.configurations ?? []);
    const affectedProducts = cpeMatches.map((match) => this.productNameNormalizer.normalize(sanitizeText(match.criteria ?? ""))).filter(Boolean);
    const affectedPackages = cpeMatches.map((match) => this.toAffectedPackage(match)).filter((affectedPackage) => affectedPackage !== null);
    const cwes = uniqueNonEmpty3(
      (cve.weaknesses ?? []).flatMap((weakness) => weakness.description ?? []).filter((descriptionItem) => descriptionItem.lang === "en").map((descriptionItem) => sanitizeText(descriptionItem.value ?? "")).filter((cwe) => /^CWE-\d+$/i.test(cwe))
    );
    const vendors = uniqueNonEmpty3(affectedPackages.map((affectedPackage) => affectedPackage.vendor ?? ""));
    const packages = uniqueNonEmpty3(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const vulnerableVersionRanges = uniqueNonEmpty3(
      affectedPackages.map(
        (affectedPackage) => affectedPackage.vulnerableVersionRange ? `${affectedPackage.vendor ? `${affectedPackage.vendor} ` : ""}${affectedPackage.name}: ${affectedPackage.vulnerableVersionRange}` : ""
      )
    );
    const publishedAt = cve.published ?? (/* @__PURE__ */ new Date(0)).toISOString();
    const updatedAt = cve.lastModified ?? publishedAt;
    const cveId = sanitizeText(cve.id ?? "");
    const nvdUrl = cveId ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` : "";
    const sourceUrls = {};
    if (nvdUrl) sourceUrls.html = nvdUrl;
    const metadata = {};
    if (cveId) {
      metadata.cveId = cveId;
      metadata.identifiers = [cveId];
    }
    if (cwes.length > 0) metadata.cwes = cwes;
    if (vendors.length > 0) metadata.vendors = vendors;
    if (packages.length > 0) metadata.packages = packages;
    if (affectedPackages.length > 0) metadata.affectedPackages = affectedPackages;
    if (vulnerableVersionRanges.length > 0) metadata.vulnerableVersionRanges = vulnerableVersionRanges;
    if (Object.keys(sourceUrls).length > 0) metadata.sourceUrls = sourceUrls;
    return {
      id: cveId || "unknown",
      source: this.sourceName,
      title: toSentenceTitle(description, cveId || "Unknown CVE"),
      summary: sanitizeMarkdown(description),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: uniqueNonEmpty3([nvdUrl, ...refs]),
      affectedProducts: uniqueNonEmpty3(affectedProducts),
      ...Object.keys(metadata).length > 0 ? { metadata } : {}
    };
  }
  collectCpeMatches(configurations) {
    const matches = [];
    const visitNode = (node) => {
      matches.push(...(node.cpeMatch ?? []).filter((match) => match.vulnerable !== false && Boolean(match.criteria)));
      for (const child of node.nodes ?? []) {
        visitNode(child);
      }
    };
    for (const configuration of configurations) {
      for (const node of configuration.nodes ?? []) {
        visitNode(node);
      }
    }
    return matches;
  }
  parseCpe(criteria) {
    const parts = criteria.split(":");
    return {
      vendor: cleanCpeToken(parts[3] ?? ""),
      product: cleanCpeToken(parts[4] ?? ""),
      version: cleanCpeToken(parts[5] ?? "")
    };
  }
  toAffectedPackage(match) {
    const criteria = match.criteria ?? "";
    const parsed = this.parseCpe(criteria);
    const product = this.productNameNormalizer.normalize(parsed.product);
    if (!product) {
      return null;
    }
    const vendor = this.productNameNormalizer.normalize(parsed.vendor);
    const vulnerableVersionRange = buildVersionRange(match, parsed.version);
    return {
      ...criteria ? { cpe: criteria } : {},
      name: product,
      ...vendor ? { vendor } : {},
      ...parsed.version && parsed.version !== "*" && parsed.version !== "-" ? { version: parsed.version } : {},
      ...vulnerableVersionRange ? { vulnerableVersionRange } : {}
    };
  }
};

// src/infrastructure/clients/nvd/NvdValidators.ts
var NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
var NVD_RESULTS_PER_PAGE = 100;
var NVD_MAX_START_INDEX = 1e6;
var ISO_8601_UTC_REGEX = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
function validateIsoUtcDate(value, fieldName) {
  const trimmed = value.trim();
  if (trimmed.length === 0) {
    throw new Error(`${fieldName} must not be empty.`);
  }
  if (!ISO_8601_UTC_REGEX.test(trimmed)) {
    throw new Error(
      `${fieldName} must be a valid ISO-8601 UTC timestamp like 2026-04-15T00:00:00.000Z.`
    );
  }
  const timestamp = Date.parse(trimmed);
  if (Number.isNaN(timestamp)) {
    throw new Error(`${fieldName} is not a valid date.`);
  }
  return trimmed;
}
function validateDateRange(since, until) {
  const safeSince = since ? validateIsoUtcDate(since, "lastModStartDate") : void 0;
  const safeUntil = until ? validateIsoUtcDate(until, "lastModEndDate") : void 0;
  if (safeSince && safeUntil && Date.parse(safeSince) > Date.parse(safeUntil)) {
    throw new Error("lastModStartDate must be less than or equal to lastModEndDate.");
  }
  return {
    ...safeSince ? { since: safeSince } : {},
    ...safeUntil ? { until: safeUntil } : {}
  };
}
function validatePublishedDateRange(publishedFrom, publishedUntil) {
  const safePublishedFrom = publishedFrom ? validateIsoUtcDate(publishedFrom, "pubStartDate") : void 0;
  const safePublishedUntil = publishedUntil ? validateIsoUtcDate(publishedUntil, "pubEndDate") : void 0;
  if (safePublishedFrom && safePublishedUntil && Date.parse(safePublishedFrom) > Date.parse(safePublishedUntil)) {
    throw new Error("pubStartDate must be less than or equal to pubEndDate.");
  }
  return {
    ...safePublishedFrom ? { publishedFrom: safePublishedFrom } : {},
    ...safePublishedUntil ? { publishedUntil: safePublishedUntil } : {}
  };
}
function validateModifiedDateRange(modifiedFrom, modifiedUntil) {
  const safeModifiedFrom = modifiedFrom ? validateIsoUtcDate(modifiedFrom, "lastModStartDate") : void 0;
  const safeModifiedUntil = modifiedUntil ? validateIsoUtcDate(modifiedUntil, "lastModEndDate") : void 0;
  if (safeModifiedFrom && safeModifiedUntil && Date.parse(safeModifiedFrom) > Date.parse(safeModifiedUntil)) {
    throw new Error("lastModStartDate must be less than or equal to lastModEndDate.");
  }
  return {
    ...safeModifiedFrom ? { modifiedFrom: safeModifiedFrom } : {},
    ...safeModifiedUntil ? { modifiedUntil: safeModifiedUntil } : {}
  };
}
function validateStartIndex(startIndex) {
  if (!Number.isInteger(startIndex)) {
    throw new Error("startIndex must be an integer.");
  }
  if (startIndex < 0) {
    throw new Error("startIndex must be greater than or equal to 0.");
  }
  if (startIndex > NVD_MAX_START_INDEX) {
    throw new Error(`startIndex exceeds maximum allowed value of ${NVD_MAX_START_INDEX}.`);
  }
  return startIndex;
}
function validateApiKey(apiKey) {
  if (/[\x00-\x1F\x7F]/.test(apiKey)) {
    throw new Error("apiKey contains invalid control characters.");
  }
  const trimmed = apiKey.trim();
  if (trimmed.length === 0) {
    throw new Error("apiKey must not be empty.");
  }
  if (trimmed.length > 256) {
    throw new Error("apiKey is too long.");
  }
  return trimmed;
}

// src/infrastructure/clients/nvd/NvdRequestBuilder.ts
var NvdRequestBuilder = class {
  constructor(apiKey, dateFilterType = "modified") {
    this.apiKey = apiKey;
    this.dateFilterType = dateFilterType;
  }
  buildFetchRequest(options) {
    const safeQuery = this.buildFetchQuery(options);
    return {
      url: this.buildUrl(safeQuery),
      headers: this.buildHeaders()
    };
  }
  buildValidationRequest() {
    return {
      url: this.buildUrl({ startIndex: 0 }),
      headers: this.buildHeaders()
    };
  }
  buildFetchQuery(options) {
    const safeStartIndex = validateStartIndex(options.startIndex);
    const safeDateRange = validateDateRange(options.since, options.until);
    const safePublishedDateRange = validatePublishedDateRange(options.publishedFrom, options.publishedUntil);
    const safeModifiedDateRange = validateModifiedDateRange(options.modifiedFrom, options.modifiedUntil);
    return {
      startIndex: safeStartIndex,
      ...safeDateRange,
      ...safePublishedDateRange,
      ...safeModifiedDateRange
    };
  }
  buildUrl(query) {
    const params = new URLSearchParams({
      resultsPerPage: String(NVD_RESULTS_PER_PAGE),
      startIndex: String(query.startIndex)
    });
    const startParam = this.dateFilterType === "published" ? "pubStartDate" : "lastModStartDate";
    const endParam = this.dateFilterType === "published" ? "pubEndDate" : "lastModEndDate";
    const effectiveStart = this.dateFilterType === "published" ? query.publishedFrom ?? query.since : query.modifiedFrom ?? query.since;
    const effectiveEnd = this.dateFilterType === "published" ? query.publishedUntil ?? query.until : query.modifiedUntil ?? query.until;
    if (effectiveStart) {
      params.set(startParam, effectiveStart);
    }
    if (effectiveEnd) {
      params.set(endParam, effectiveEnd);
    }
    return `${NVD_BASE_URL}?${params.toString()}`;
  }
  buildHeaders() {
    const headers = {};
    if (this.apiKey) {
      headers.apiKey = validateApiKey(this.apiKey);
    }
    return headers;
  }
};

// src/infrastructure/clients/nvd/NvdClient.ts
var NvdClient = class extends ClientBase {
  constructor(httpClient, id, name, apiKey, controls, dateFilterType = "modified", dependencies = {}) {
    super(httpClient, name, controls, dependencies.logger, dependencies.retryPolicy);
    this.id = id;
    this.name = name;
    this.apiKey = apiKey;
    this.controls = controls;
    this.mapper = new NvdMapper(this.name);
    this.requestBuilder = new NvdRequestBuilder(this.apiKey, dateFilterType);
  }
  async fetchVulnerabilities(options) {
    const dedup = /* @__PURE__ */ new Set();
    const collected = [];
    const warnings = [];
    const seenIndexes = /* @__PURE__ */ new Set();
    let pagesFetched = 0;
    let retriesPerformed = 0;
    let startIndex = 0;
    while (pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenIndexes.has(startIndex)) {
        warnings.push("duplicate_start_index");
        break;
      }
      seenIndexes.add(startIndex);
      const { response, retriesPerformed: requestRetries } = await this.fetchPage({
        startIndex,
        ...options.since ? { since: options.since } : {},
        ...options.until ? { until: options.until } : {},
        ...options.publishedFrom ? { publishedFrom: options.publishedFrom } : {},
        ...options.publishedUntil ? { publishedUntil: options.publishedUntil } : {},
        ...options.modifiedFrom ? { modifiedFrom: options.modifiedFrom } : {},
        ...options.modifiedUntil ? { modifiedUntil: options.modifiedUntil } : {},
        signal: options.signal,
        operationName: "fetchVulnerabilities"
      });
      retriesPerformed += requestRetries;
      pagesFetched += 1;
      const items = (response.data.vulnerabilities ?? []).map((item) => item.cve).filter((cve) => Boolean(cve?.id)).map((cve) => this.mapper.normalize(cve));
      const filteredItems = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil ? filterVulnerabilitiesByDateWindow(items, {
        from: options.modifiedFrom ?? options.publishedFrom ?? (/* @__PURE__ */ new Date(0)).toISOString(),
        to: options.modifiedUntil ?? options.publishedUntil ?? (/* @__PURE__ */ new Date(864e13)).toISOString()
      }, options.modifiedFrom || options.modifiedUntil ? "modified" : "published") : items;
      for (const item of filteredItems) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push("max_items_reached");
          break;
        }
        const key = `${item.source}:${item.id}`;
        if (dedup.has(key)) {
          continue;
        }
        dedup.add(key);
        collected.push(item);
      }
      const nextStartIndex = (response.data.startIndex ?? startIndex) + (response.data.resultsPerPage ?? items.length);
      if (items.length === 0 || nextStartIndex >= (response.data.totalResults ?? 0)) {
        break;
      }
      startIndex = nextStartIndex;
    }
    if (pagesFetched >= this.controls.maxPages) {
      warnings.push("max_pages_reached");
    }
    return {
      vulnerabilities: collected,
      pagesFetched,
      warnings,
      retriesPerformed
    };
  }
  async validateConnection(signal) {
    await this.executeRequest(this.requestBuilder.buildValidationRequest(), signal, "validateConnection");
  }
  async fetchPage(options) {
    const request = this.requestBuilder.buildFetchRequest(options);
    return this.executeRequest(request, options.signal, options.operationName);
  }
  async executeRequest(request, signal, operationName) {
    return this.getJsonWithResilience({
      context: {
        provider: this.name,
        operation: operationName,
        url: request.url
      },
      headers: request.headers,
      signal,
      decorateError: (error) => this.decorateNvdError(error)
    });
  }
  decorateNvdError(error) {
    if (!(error instanceof ClientHttpError)) {
      return error;
    }
    if (error.metadata.status === 401) {
      return new AuthFailureHttpError(
        "NVD request unauthorized (401). Check API key validity for the configured NVD feed.",
        error.metadata
      );
    }
    if (error.metadata.status === 403) {
      return new AuthFailureHttpError(
        this.apiKey ? "NVD request forbidden (403). API key may be invalid, missing required access, or temporarily blocked by the NVD service." : "NVD request forbidden (403). Configure a valid NVD API key for this feed.",
        error.metadata
      );
    }
    return error;
  }
};

// src/infrastructure/storage/VulnCacheSchema.ts
var VULN_CACHE_DB_NAME = "vulndash-cache";
var VULN_CACHE_DB_VERSION = 3;
var VULN_CACHE_STORES = {
  componentQueries: "componentQueries",
  databaseMetadata: "database-metadata",
  syncMetadata: "sync-metadata",
  triageRecords: "triage-records",
  vulnerabilities: "vulnerabilities"
};
var VULN_CACHE_INDEXES = {
  byLastSeenAt: "by-last-seen-at",
  byRetentionRank: "by-retention-rank",
  bySourceId: "by-source-id",
  triageByState: "triage-by-state",
  triageByUpdatedAt: "triage-by-updated-at"
};
var ensureIndex = (store, name, keyPath, options) => {
  if (!store.indexNames.contains(name)) {
    store.createIndex(name, keyPath, options);
  }
};
var ensureStore = (database, name, options) => {
  if (!database.objectStoreNames.contains(name)) {
    return database.createObjectStore(name, options);
  }
  return database.transaction(name, "versionchange").objectStore(name);
};
var buildPersistedVulnerabilityKey = (sourceId, vulnerabilityId) => `${sourceId.trim()}::${vulnerabilityId.trim()}`;
var getVulnerabilityFreshnessPublishedAtMs = (vulnerability) => {
  const parsed = Date.parse(vulnerability.publishedAt);
  return Number.isFinite(parsed) ? parsed : 0;
};
var getVulnerabilityFreshnessUpdatedAtMs = (vulnerability) => {
  const updatedAtMs = Date.parse(vulnerability.updatedAt);
  if (Number.isFinite(updatedAtMs)) {
    return updatedAtMs;
  }
  return getVulnerabilityFreshnessPublishedAtMs(vulnerability);
};
var toRetentionRank = (record) => [
  record.lastSeenAtMs,
  record.freshnessUpdatedAtMs,
  record.cacheKey
];
var createPersistedVulnerabilityRecord = (sourceId, vulnerability, lastSeenAt, createdAtMs) => {
  const cacheKey = buildPersistedVulnerabilityKey(sourceId, vulnerability.id);
  const freshnessUpdatedAtMs = getVulnerabilityFreshnessUpdatedAtMs(vulnerability);
  const freshnessPublishedAtMs = getVulnerabilityFreshnessPublishedAtMs(vulnerability);
  const lastSeenAtMs = Number.isFinite(Date.parse(lastSeenAt)) ? Date.parse(lastSeenAt) : createdAtMs;
  return {
    cacheKey,
    createdAtMs,
    freshnessPublishedAtMs,
    freshnessUpdatedAtMs,
    lastSeenAt,
    lastSeenAtMs,
    retentionRank: toRetentionRank({ cacheKey, freshnessUpdatedAtMs, lastSeenAtMs }),
    sourceId,
    vulnerability,
    vulnerabilityId: vulnerability.id
  };
};
var createPersistedTriageRecord = (record) => ({
  correlationKey: record.correlationKey,
  vulnerabilityId: record.vulnerabilityId,
  source: record.source,
  state: record.state,
  updatedAt: record.updatedAt,
  updatedAtMs: Number.isFinite(Date.parse(record.updatedAt)) ? Date.parse(record.updatedAt) : 0,
  ...record.reason ? { reason: record.reason } : {},
  ...record.ticketRef ? { ticketRef: record.ticketRef } : {},
  ...record.updatedBy ? { updatedBy: record.updatedBy } : {}
});
var comparePersistedRecordsForHardCap = (left, right) => right.lastSeenAtMs - left.lastSeenAtMs || right.freshnessUpdatedAtMs - left.freshnessUpdatedAtMs || right.freshnessPublishedAtMs - left.freshnessPublishedAtMs || left.cacheKey.localeCompare(right.cacheKey);
var applyVulnCacheSchemaUpgrade = (database, oldVersion, _newVersion) => {
  const vulnerabilities = ensureStore(database, VULN_CACHE_STORES.vulnerabilities, {
    keyPath: "cacheKey"
  });
  ensureIndex(vulnerabilities, VULN_CACHE_INDEXES.bySourceId, "sourceId", { unique: false });
  ensureIndex(vulnerabilities, VULN_CACHE_INDEXES.byLastSeenAt, "lastSeenAtMs", { unique: false });
  ensureIndex(vulnerabilities, VULN_CACHE_INDEXES.byRetentionRank, "retentionRank", { unique: false });
  ensureStore(database, VULN_CACHE_STORES.syncMetadata, {
    keyPath: "sourceId"
  });
  ensureStore(database, VULN_CACHE_STORES.databaseMetadata, {
    keyPath: "key"
  });
  const triageRecords = ensureStore(database, VULN_CACHE_STORES.triageRecords, {
    keyPath: "correlationKey"
  });
  ensureIndex(triageRecords, VULN_CACHE_INDEXES.triageByState, "state", { unique: false });
  ensureIndex(triageRecords, VULN_CACHE_INDEXES.triageByUpdatedAt, "updatedAtMs", { unique: false });
  if (oldVersion < 3 || !database.objectStoreNames.contains(VULN_CACHE_STORES.componentQueries)) {
    ensureStore(database, VULN_CACHE_STORES.componentQueries, {
      keyPath: "purl"
    });
  }
};

// src/infrastructure/clients/osv/OsvCacheKey.ts
var DEFAULT_OSV_CACHE_SOURCE_ID = BUILT_IN_FEEDS.OSV.type;
var buildOsvVulnerabilityCacheKey = (vulnerabilityId, sourceId = DEFAULT_OSV_CACHE_SOURCE_ID) => buildPersistedVulnerabilityKey(sourceId, vulnerabilityId);

// src/infrastructure/clients/osv/OsvMapper.ts
var OSV_HTML_URL_PREFIX = "https://osv.dev/vulnerability/";
var OSV_API_URL_PREFIX = "https://api.osv.dev/v1/vulns/";
var severityToRepresentativeScore = (severity) => {
  switch (severity) {
    case "CRITICAL":
      return 9.5;
    case "HIGH":
      return 8;
    case "MEDIUM":
      return 5.5;
    case "LOW":
      return 2.5;
    case "NONE":
    default:
      return 0;
  }
};
var uniqueNonEmpty4 = (values) => {
  const seen = /* @__PURE__ */ new Set();
  const result = [];
  for (const value of values) {
    const trimmed = sanitizeText(value);
    if (!trimmed) {
      continue;
    }
    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(trimmed);
  }
  return result;
};
var normalizeSeverityLabel = (value) => {
  const normalized = sanitizeText(value ?? "").toLowerCase();
  switch (normalized) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
    case "moderate":
      return "MEDIUM";
    case "low":
      return "LOW";
    case "none":
    case "informational":
    case "info":
    case "unknown":
    case "unscored":
      return "NONE";
    default:
      return void 0;
  }
};
var extractNumericCvssScore = (severity) => {
  if (!severity.type.toUpperCase().startsWith("CVSS")) {
    return void 0;
  }
  const parsed = Number.parseFloat(severity.score);
  if (Number.isFinite(parsed) && parsed >= 0) {
    return parsed;
  }
  return void 0;
};
var collectSeverityPayloads = (payload) => [
  ...payload.severity ?? [],
  ...(payload.affected ?? []).flatMap((affected) => affected.severity ?? [])
];
var resolveSeverity = (payload) => {
  for (const severityPayload of collectSeverityPayloads(payload)) {
    const cvssScore = extractNumericCvssScore(severityPayload);
    if (cvssScore !== void 0) {
      return {
        cvssScore,
        severity: classifySeverity(cvssScore)
      };
    }
  }
  const databaseSpecificSeverity = normalizeSeverityLabel(
    payload.database_specific?.severity ?? payload.affected?.find((affected) => affected.database_specific?.severity)?.database_specific?.severity
  );
  if (databaseSpecificSeverity) {
    return {
      cvssScore: severityToRepresentativeScore(databaseSpecificSeverity),
      severity: databaseSpecificSeverity
    };
  }
  const fallbackSeverity = normalizeSeverityLabel(
    collectSeverityPayloads(payload).map((severityPayload) => severityPayload.score).find((value) => normalizeSeverityLabel(value) !== void 0) ?? payload.affected?.find((affected) => normalizeSeverityLabel(affected.ecosystem_specific?.severity) !== void 0)?.ecosystem_specific?.severity
  );
  if (fallbackSeverity) {
    return {
      cvssScore: severityToRepresentativeScore(fallbackSeverity),
      severity: fallbackSeverity
    };
  }
  return {
    cvssScore: 0,
    severity: "NONE"
  };
};
var stripPurlVersion = (purl) => {
  const hashIndex = purl.indexOf("#");
  const withoutSubpath = hashIndex >= 0 ? purl.slice(0, hashIndex) : purl;
  const queryIndex = withoutSubpath.indexOf("?");
  const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
  const lastAt = withoutQualifiers.lastIndexOf("@");
  const lastSlash = withoutQualifiers.lastIndexOf("/");
  if (lastAt > lastSlash) {
    return withoutQualifiers.slice(0, lastAt);
  }
  return withoutQualifiers;
};
var extractPurlVersion = (purl) => {
  const hashIndex = purl.indexOf("#");
  const withoutSubpath = hashIndex >= 0 ? purl.slice(0, hashIndex) : purl;
  const queryIndex = withoutSubpath.indexOf("?");
  const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
  const lastAt = withoutQualifiers.lastIndexOf("@");
  const lastSlash = withoutQualifiers.lastIndexOf("/");
  if (lastAt > lastSlash && lastAt < withoutQualifiers.length - 1) {
    return withoutQualifiers.slice(lastAt + 1);
  }
  return void 0;
};
var buildVersionRange2 = (affected) => {
  const ranges = (affected.ranges ?? []).flatMap((range) => range.events.map((event) => ({
    introduced: sanitizeText(event.introduced ?? ""),
    fixed: sanitizeText(event.fixed ?? ""),
    lastAffected: sanitizeText(event.last_affected ?? ""),
    limit: sanitizeText(event.limit ?? "")
  })));
  const parts = uniqueNonEmpty4(ranges.flatMap((range) => [
    range.introduced && range.introduced !== "0" ? `>= ${range.introduced}` : "",
    range.fixed ? `< ${range.fixed}` : "",
    range.lastAffected ? `<= ${range.lastAffected}` : "",
    range.limit ? `limit ${range.limit}` : ""
  ]));
  if (parts.length > 0) {
    return parts.join(", ");
  }
  const versions = uniqueNonEmpty4((affected.versions ?? []).map((version) => sanitizeText(version)));
  if (versions.length > 0) {
    return versions.join(", ");
  }
  return void 0;
};
var toAffectedPackage = (affected) => {
  const normalizedPurl = PurlNormalizer.normalize(affected.package?.purl);
  const packageName = sanitizeText(affected.package?.name ?? "");
  const ecosystem = sanitizeText(affected.package?.ecosystem ?? "");
  if (!normalizedPurl && !packageName) {
    return null;
  }
  const version = normalizedPurl ? extractPurlVersion(normalizedPurl) : void 0;
  const vulnerableVersionRange = buildVersionRange2(affected);
  return {
    name: packageName || stripPurlVersion(normalizedPurl ?? ""),
    ...ecosystem ? { ecosystem } : {},
    ...normalizedPurl ? { purl: normalizedPurl } : {},
    ...version ? { version } : {},
    ...vulnerableVersionRange ? { vulnerableVersionRange } : {}
  };
};
var buildStableId = (payload) => {
  const explicitId = sanitizeText(payload.id ?? "");
  if (explicitId) {
    return explicitId;
  }
  const aliasId = uniqueNonEmpty4(payload.aliases ?? [])[0];
  if (aliasId) {
    return aliasId;
  }
  const summary = sanitizeText(payload.summary ?? payload.details ?? "");
  const modified = sanitizeText(payload.modified ?? payload.published ?? "");
  return summary || modified || "unknown";
};
var OsvMapper = class {
  constructor(sourceName) {
    this.sourceName = sourceName;
  }
  normalize(payload) {
    const id = buildStableId(payload);
    const publishedAt = sanitizeText(payload.published ?? payload.modified ?? (/* @__PURE__ */ new Date(0)).toISOString());
    const updatedAt = sanitizeText(payload.modified ?? publishedAt);
    const title = sanitizeText(payload.summary ?? id ?? "OSV Advisory");
    const summary = sanitizeMarkdown(payload.details ?? payload.summary ?? "No summary provided");
    const { cvssScore, severity } = resolveSeverity(payload);
    const affectedPackages = (payload.affected ?? []).map((affected) => toAffectedPackage(affected)).filter((affectedPackage) => affectedPackage !== null);
    const affectedProducts = uniqueNonEmpty4(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const aliases = uniqueNonEmpty4(payload.aliases ?? []);
    const related = uniqueNonEmpty4(payload.related ?? []);
    const upstream = uniqueNonEmpty4(payload.upstream ?? []);
    const identifiers = uniqueNonEmpty4([id, ...aliases, ...related, ...upstream]);
    const packages = uniqueNonEmpty4(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const vulnerableVersionRanges = uniqueNonEmpty4(affectedPackages.map((affectedPackage) => affectedPackage.vulnerableVersionRange ? `${affectedPackage.name}: ${affectedPackage.vulnerableVersionRange}` : ""));
    const apiUrl = sanitizeUrl(`${OSV_API_URL_PREFIX}${encodeURIComponent(id)}`);
    const htmlUrl = sanitizeUrl(`${OSV_HTML_URL_PREFIX}${encodeURIComponent(id)}`);
    const sourceUrl = sanitizeUrl(payload.database_specific?.source ?? "");
    const references = uniqueNonEmpty4([
      htmlUrl,
      sourceUrl,
      ...(payload.references ?? []).map((reference) => sanitizeUrl(reference.url))
    ]);
    const sourceUrls = {};
    if (apiUrl) {
      sourceUrls.api = apiUrl;
    }
    if (htmlUrl) {
      sourceUrls.html = htmlUrl;
    }
    if (sourceUrl) {
      sourceUrls.repositoryAdvisory = sourceUrl;
    }
    const metadata = {};
    const cveId = identifiers.find((identifier) => identifier.toUpperCase().startsWith("CVE-"));
    if (cveId) {
      metadata.cveId = cveId;
    }
    if (identifiers.length > 0) {
      metadata.identifiers = identifiers;
    }
    const metadataAliases = uniqueNonEmpty4(aliases.filter((alias) => alias !== cveId && alias !== id));
    if (metadataAliases.length > 0) {
      metadata.aliases = metadataAliases;
    }
    if (packages.length > 0) {
      metadata.packages = packages;
    }
    if (affectedPackages.length > 0) {
      metadata.affectedPackages = affectedPackages;
    }
    if (vulnerableVersionRanges.length > 0) {
      metadata.vulnerableVersionRanges = vulnerableVersionRanges;
    }
    if (Object.keys(sourceUrls).length > 0) {
      metadata.sourceUrls = sourceUrls;
    }
    return {
      id,
      source: this.sourceName,
      title,
      summary,
      publishedAt,
      updatedAt,
      cvssScore,
      severity,
      references,
      affectedProducts,
      ...Object.keys(metadata).length > 0 ? { metadata } : {}
    };
  }
};

// src/infrastructure/clients/osv/OsvFeedClient.ts
var OsvFeedClient = class extends ClientBase {
  constructor(httpClient, queryCache, getPurls, controls, config) {
    super(httpClient, config.name, controls);
    this.queryCache = queryCache;
    this.getPurls = getPurls;
    this.controls = controls;
    this.config = config;
    this.syncMode = "snapshot";
    this.id = config.id;
    this.name = config.name;
    this.mapper = new OsvMapper(config.name);
  }
  async fetchVulnerabilities(options) {
    const warnings = [];
    const seenAtMs = Date.now();
    const { ignoredCount, purls, rawCount } = await this.loadNormalizedActivePurls();
    const activePurls = purls;
    const activePurlSet = new Set(activePurls);
    if (ignoredCount > 0) {
      warnings.push("ignored_invalid_purls");
    }
    await this.queryCache.markComponentQueriesSeen(activePurls, seenAtMs);
    const orphanPrunedCount = await this.queryCache.pruneOrphanedComponentQueries(activePurlSet);
    const expiredPrunedCount = await this.queryCache.pruneExpiredComponentQueries(
      seenAtMs - Math.max(this.config.cacheTtlMs, this.config.negativeCacheTtlMs)
    );
    if (activePurls.length === 0) {
      this.logFetchPlan({
        cacheErrorStateCount: 0,
        cacheHitCount: 0,
        cacheMissCount: 0,
        cacheStaleCount: 0,
        expiredPrunedCount,
        normalizedValidPurlCount: 0,
        orphanPrunedCount,
        rawActivePurlCount: rawCount
      });
      this.logFetchComplete({
        batchCount: 0,
        continuationCount: 0,
        mappedVulnerabilityCount: 0,
        partialFailureCount: 0,
        pruneExpiredCount: expiredPrunedCount,
        pruneOrphanedCount: orphanPrunedCount,
        retriesPerformed: 0,
        returnedVulnerabilityCount: 0,
        warnings
      });
      return {
        vulnerabilities: [],
        pagesFetched: 0,
        warnings,
        retriesPerformed: 0
      };
    }
    const recordsByPurl = await this.queryCache.loadComponentQueries(activePurls);
    const classifications = activePurls.map((purl) => this.evaluateFreshness(purl, recordsByPurl.get(purl), seenAtMs));
    const classificationSummary = this.summarizeClassifications(classifications);
    this.logFetchPlan({
      ...classificationSummary,
      expiredPrunedCount,
      normalizedValidPurlCount: activePurls.length,
      orphanPrunedCount,
      rawActivePurlCount: rawCount
    });
    const freshPositiveRecords = classifications.filter((classification) => classification.freshness === "fresh-positive" && Boolean(classification.record)).map((classification) => classification.record);
    const cachedVulnerabilities = await this.rehydrateCachedVulnerabilities(freshPositiveRecords);
    const purlsToQuery = classifications.filter((classification) => classification.freshness === "missing" || classification.freshness === "stale" || classification.freshness === "error-state").map((classification) => classification.purl);
    const queryResult = await this.fetchQueriedPurls(purlsToQuery, options.signal);
    const queriedAtMs = Date.now();
    if (queryResult.maxPagesReached) {
      warnings.push("max_pages_reached");
    }
    if (queryResult.failedPurls.length > 0) {
      warnings.push("partial_failure");
    }
    const fallbackRecords = this.selectFailedFallbackRecords(queryResult.failedPurls, recordsByPurl);
    const fallbackVulnerabilities = await this.rehydrateCachedVulnerabilities(fallbackRecords);
    const queryRecords = [
      ...this.buildSuccessfulQueryRecords(queryResult.resultsByPurl, queriedAtMs, seenAtMs),
      ...this.buildErrorQueryRecords(queryResult.failedPurls, recordsByPurl, queriedAtMs, seenAtMs)
    ];
    if (queryRecords.length > 0) {
      await this.queryCache.saveComponentQueries(queryRecords);
    }
    const queriedVulnerabilities = Array.from(queryResult.resultsByPurl.values()).flatMap((vulnerabilities2) => vulnerabilities2);
    const vulnerabilities = Array.from(this.dedupeVulnerabilities([
      ...cachedVulnerabilities,
      ...fallbackVulnerabilities,
      ...queriedVulnerabilities
    ]));
    this.logFetchComplete({
      batchCount: queryResult.pagesFetched,
      continuationCount: queryResult.continuationCount,
      mappedVulnerabilityCount: queryResult.mappedVulnerabilityCount,
      partialFailureCount: queryResult.failedPurls.length,
      pruneExpiredCount: expiredPrunedCount,
      pruneOrphanedCount: orphanPrunedCount,
      retriesPerformed: queryResult.retriesPerformed,
      returnedVulnerabilityCount: vulnerabilities.length,
      warnings
    });
    if (queryResult.failedPurls.length > 0) {
      console.warn("[vulndash.osv.fetch.partial_failure]", {
        source: this.name,
        feedId: this.id,
        partialFailureCount: queryResult.failedPurls.length,
        batchCount: queryResult.pagesFetched
      });
    }
    return {
      vulnerabilities,
      pagesFetched: queryResult.pagesFetched,
      warnings,
      retriesPerformed: queryResult.retriesPerformed
    };
  }
  async loadNormalizedActivePurls() {
    const rawPurls = await this.getPurls();
    const normalizedPurls = [];
    const seen = /* @__PURE__ */ new Set();
    let ignoredCount = 0;
    for (const rawPurl of rawPurls) {
      const normalized = this.normalizeResolvablePurl(rawPurl);
      if (!normalized) {
        ignoredCount += 1;
        continue;
      }
      if (seen.has(normalized)) {
        continue;
      }
      seen.add(normalized);
      normalizedPurls.push(normalized);
    }
    normalizedPurls.sort((left, right) => left.localeCompare(right));
    return {
      ignoredCount,
      purls: normalizedPurls,
      rawCount: rawPurls.length
    };
  }
  normalizeResolvablePurl(rawPurl) {
    const normalized = PurlNormalizer.normalize(rawPurl);
    if (!normalized || !normalized.startsWith("pkg:")) {
      return null;
    }
    const pathWithoutQualifiers = normalized.slice(4).split("#", 1)[0]?.split("?", 1)[0]?.replace(/^\/+/, "")?.replace(/\/+$/, "") ?? "";
    if (!pathWithoutQualifiers || !pathWithoutQualifiers.includes("/")) {
      return null;
    }
    const lastAt = pathWithoutQualifiers.lastIndexOf("@");
    const lastSlash = pathWithoutQualifiers.lastIndexOf("/");
    if (lastAt <= lastSlash || lastAt === pathWithoutQualifiers.length - 1) {
      return null;
    }
    return normalized;
  }
  evaluateFreshness(purl, record, nowMs) {
    if (!record) {
      return { freshness: "missing", purl };
    }
    if (record.resultState === "error") {
      return { freshness: "error-state", purl, record };
    }
    const ageMs = Math.max(0, nowMs - record.lastQueriedAtMs);
    if (record.resultState === "hit" && ageMs <= this.config.cacheTtlMs) {
      return { freshness: "fresh-positive", purl, record };
    }
    if (record.resultState === "miss" && ageMs <= this.config.negativeCacheTtlMs) {
      return { freshness: "fresh-negative", purl, record };
    }
    return { freshness: "stale", purl, record };
  }
  async rehydrateCachedVulnerabilities(records) {
    const keys = records.flatMap((record) => record.vulnerabilityCacheKeys);
    if (keys.length === 0) {
      return [];
    }
    const loaded = await this.queryCache.loadVulnerabilitiesByCacheKeys(keys);
    return this.dedupeVulnerabilities(loaded);
  }
  async fetchQueriedPurls(purls, signal) {
    if (purls.length === 0) {
      return {
        continuationCount: 0,
        failedPurls: [],
        mappedVulnerabilityCount: 0,
        maxPagesReached: false,
        pagesFetched: 0,
        resultsByPurl: /* @__PURE__ */ new Map(),
        retriesPerformed: 0
      };
    }
    const chunks = this.chunkPurls(purls, this.config.osvMaxBatchSize);
    const chunkResults = await this.processWithConcurrency(
      chunks,
      this.config.maxConcurrentBatches,
      async (chunk) => this.fetchChunk(chunk, signal)
    );
    let continuationCount = 0;
    const failedPurls = [];
    let mappedVulnerabilityCount = 0;
    let maxPagesReached = false;
    const resultsByPurl = /* @__PURE__ */ new Map();
    let pagesFetched = 0;
    let retriesPerformed = 0;
    for (const chunkResult of chunkResults) {
      continuationCount += chunkResult.continuationCount;
      pagesFetched += chunkResult.pagesFetched;
      retriesPerformed += chunkResult.retriesPerformed;
      failedPurls.push(...chunkResult.failedPurls);
      mappedVulnerabilityCount += chunkResult.mappedVulnerabilityCount;
      maxPagesReached = maxPagesReached || chunkResult.maxPagesReached;
      for (const [purl, vulnerabilities] of chunkResult.resultsByPurl) {
        resultsByPurl.set(purl, vulnerabilities);
      }
    }
    return {
      continuationCount,
      failedPurls: Array.from(new Set(failedPurls)).sort((left, right) => left.localeCompare(right)),
      mappedVulnerabilityCount,
      maxPagesReached,
      pagesFetched,
      resultsByPurl,
      retriesPerformed
    };
  }
  chunkPurls(purls, chunkSize) {
    const chunks = [];
    for (let index = 0; index < purls.length; index += chunkSize) {
      chunks.push(purls.slice(index, index + chunkSize));
    }
    return chunks;
  }
  async fetchChunk(purls, signal) {
    const accumulated = /* @__PURE__ */ new Map();
    const failedPurls = /* @__PURE__ */ new Set();
    let continuationCount = 0;
    let pending = purls.map((purl) => ({ pageToken: void 0, purl }));
    let maxPagesReached = false;
    let pagesFetched = 0;
    let retriesPerformed = 0;
    while (pending.length > 0 && pagesFetched < this.controls.maxPages) {
      const requestItems = pending.map((query) => this.toBatchQueryItem(query.purl, query.pageToken));
      try {
        const { response, retriesPerformed: requestRetries } = await this.executeBatchQuery(requestItems, signal);
        pagesFetched += 1;
        retriesPerformed += requestRetries;
        const association = this.associateBatchResponse(pending, response, accumulated);
        continuationCount += association.continuationCount;
        for (const purl of association.failedPurls) {
          failedPurls.add(purl);
        }
        pending = [...association.nextPending];
      } catch {
        for (const query of pending) {
          accumulated.delete(query.purl);
          failedPurls.add(query.purl);
        }
        return {
          continuationCount,
          failedPurls: Array.from(failedPurls).sort((left, right) => left.localeCompare(right)),
          mappedVulnerabilityCount: this.countMappedVulnerabilities(accumulated),
          maxPagesReached,
          pagesFetched,
          resultsByPurl: this.mapAccumulatedPayloads(accumulated),
          retriesPerformed
        };
      }
    }
    if (pending.length > 0) {
      maxPagesReached = true;
      for (const query of pending) {
        accumulated.delete(query.purl);
        failedPurls.add(query.purl);
      }
    }
    return {
      continuationCount,
      failedPurls: Array.from(failedPurls).sort((left, right) => left.localeCompare(right)),
      mappedVulnerabilityCount: this.countMappedVulnerabilities(accumulated),
      maxPagesReached,
      pagesFetched,
      resultsByPurl: this.mapAccumulatedPayloads(accumulated),
      retriesPerformed
    };
  }
  toBatchQueryItem(purl, pageToken) {
    return {
      package: { purl },
      ...pageToken ? { page_token: pageToken } : {}
    };
  }
  async executeBatchQuery(queries, parentSignal) {
    const timedSignal = this.createTimedSignal(parentSignal, this.config.requestTimeoutMs);
    try {
      return await this.postJsonWithResilience({
        body: { queries },
        context: {
          provider: this.name,
          operation: "fetchVulnerabilities",
          url: this.config.osvEndpointUrl
        },
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": "obsidian-vulndash"
        },
        signal: timedSignal.signal
      });
    } finally {
      timedSignal.cleanup();
    }
  }
  createTimedSignal(parentSignal, timeoutMs) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    const abortParent = () => controller.abort();
    parentSignal.addEventListener("abort", abortParent, { once: true });
    return {
      cleanup: () => {
        clearTimeout(timeoutId);
        parentSignal.removeEventListener("abort", abortParent);
      },
      signal: controller.signal
    };
  }
  associateBatchResponse(pending, response, accumulated) {
    let continuationCount = 0;
    const failedPurls = [];
    const nextPending = [];
    for (let index = 0; index < pending.length; index += 1) {
      const query = pending[index];
      if (!query) {
        continue;
      }
      const result = response.data.results?.[index];
      if (!result) {
        accumulated.delete(query.purl);
        failedPurls.push(query.purl);
        continue;
      }
      const existing = accumulated.get(query.purl) ?? [];
      if (result.vulns) {
        existing.push(...result.vulns);
      }
      accumulated.set(query.purl, existing);
      const nextPageToken = result.next_page_token?.trim();
      if (nextPageToken) {
        continuationCount += 1;
        nextPending.push({
          pageToken: nextPageToken,
          purl: query.purl
        });
      }
    }
    return {
      continuationCount,
      failedPurls,
      nextPending
    };
  }
  mapAccumulatedPayloads(accumulated) {
    const resultsByPurl = /* @__PURE__ */ new Map();
    for (const [purl, payloads] of accumulated) {
      resultsByPurl.set(purl, this.dedupeVulnerabilities(payloads.map((payload) => this.mapper.normalize(payload))));
    }
    return resultsByPurl;
  }
  buildSuccessfulQueryRecords(resultsByPurl, queriedAtMs, seenAtMs) {
    const records = [];
    for (const [purl, vulnerabilities] of resultsByPurl) {
      records.push({
        purl,
        source: BUILT_IN_FEEDS.OSV.type,
        lastQueriedAtMs: queriedAtMs,
        lastSeenInWorkspaceAtMs: seenAtMs,
        resultState: vulnerabilities.length > 0 ? "hit" : "miss",
        vulnerabilityCacheKeys: vulnerabilities.length > 0 ? this.toDeterministicCacheKeys(vulnerabilities) : []
      });
    }
    return records;
  }
  buildErrorQueryRecords(purls, existingRecordsByPurl, queriedAtMs, seenAtMs) {
    return purls.map((purl) => ({
      purl,
      source: BUILT_IN_FEEDS.OSV.type,
      lastQueriedAtMs: queriedAtMs,
      lastSeenInWorkspaceAtMs: seenAtMs,
      resultState: "error",
      vulnerabilityCacheKeys: [...existingRecordsByPurl.get(purl)?.vulnerabilityCacheKeys ?? []]
    }));
  }
  selectFailedFallbackRecords(failedPurls, recordsByPurl) {
    const fallbackRecords = [];
    for (const purl of failedPurls) {
      const record = recordsByPurl.get(purl);
      if (!record || record.vulnerabilityCacheKeys.length === 0) {
        continue;
      }
      fallbackRecords.push(record);
    }
    return fallbackRecords;
  }
  toDeterministicCacheKeys(vulnerabilities) {
    return Array.from(new Set(vulnerabilities.map((vulnerability) => buildOsvVulnerabilityCacheKey(vulnerability.id, this.id)))).sort((left, right) => left.localeCompare(right));
  }
  countMappedVulnerabilities(accumulated) {
    let mappedVulnerabilityCount = 0;
    for (const payloads of accumulated.values()) {
      mappedVulnerabilityCount += payloads.length;
    }
    return mappedVulnerabilityCount;
  }
  dedupeVulnerabilities(vulnerabilities) {
    const deduped = /* @__PURE__ */ new Map();
    for (const vulnerability of vulnerabilities) {
      deduped.set(buildVulnerabilityCacheKey(vulnerability), vulnerability);
    }
    return sortVulnerabilitiesDeterministically(deduped.values());
  }
  summarizeClassifications(classifications) {
    let cacheErrorStateCount = 0;
    let cacheHitCount = 0;
    let cacheMissCount = 0;
    let cacheStaleCount = 0;
    for (const classification of classifications) {
      switch (classification.freshness) {
        case "fresh-positive":
          cacheHitCount += 1;
          break;
        case "fresh-negative":
        case "missing":
          cacheMissCount += 1;
          break;
        case "stale":
          cacheStaleCount += 1;
          break;
        case "error-state":
          cacheErrorStateCount += 1;
          break;
        default:
          break;
      }
    }
    return {
      cacheErrorStateCount,
      cacheHitCount,
      cacheMissCount,
      cacheStaleCount
    };
  }
  logFetchPlan(context) {
    console.info("[vulndash.osv.fetch.plan]", {
      source: this.name,
      feedId: this.id,
      rawActivePurlCount: context.rawActivePurlCount,
      normalizedValidPurlCount: context.normalizedValidPurlCount,
      cacheHitCount: context.cacheHitCount,
      cacheMissCount: context.cacheMissCount,
      cacheStaleCount: context.cacheStaleCount,
      cacheErrorStateCount: context.cacheErrorStateCount,
      pruneOrphanedCount: context.orphanPrunedCount,
      pruneExpiredCount: context.expiredPrunedCount
    });
  }
  logFetchComplete(context) {
    console.info("[vulndash.osv.fetch.complete]", {
      source: this.name,
      feedId: this.id,
      osvBatchCount: context.batchCount,
      continuationCount: context.continuationCount,
      mappedVulnerabilityCount: context.mappedVulnerabilityCount,
      returnedVulnerabilityCount: context.returnedVulnerabilityCount,
      partialFailureCount: context.partialFailureCount,
      pruneOrphanedCount: context.pruneOrphanedCount,
      pruneExpiredCount: context.pruneExpiredCount,
      retriesPerformed: context.retriesPerformed,
      warnings: [...context.warnings]
    });
  }
  async processWithConcurrency(items, concurrency, worker) {
    if (items.length === 0) {
      return [];
    }
    const results = new Array(items.length);
    let nextIndex = 0;
    const workerCount = Math.max(1, Math.min(concurrency, items.length));
    await Promise.all(Array.from({ length: workerCount }, async () => {
      while (nextIndex < items.length) {
        const currentIndex = nextIndex;
        nextIndex += 1;
        results[currentIndex] = await worker(items[currentIndex], currentIndex);
      }
    }));
    return results;
  }
};

// src/infrastructure/factories/FeedFactory.ts
var buildFeedsFromConfig = (configs, httpClient, controls, dependencies = {}) => {
  const feeds = [];
  for (const config of configs) {
    if (!config.enabled) {
      continue;
    }
    switch (config.type) {
      case FEED_TYPES.NVD: {
        feeds.push(new NvdClient(
          httpClient,
          config.id,
          config.name,
          config.apiKey ?? config.token ?? "",
          controls,
          config.dateFilterType
          // Pass the setting here
        ));
        break;
      }
      case FEED_TYPES.GITHUB_ADVISORY: {
        feeds.push(new GitHubAdvisoryClient(httpClient, config.id, config.name, config.token ?? "", controls));
        break;
      }
      case FEED_TYPES.GITHUB_REPO: {
        const repoPath = config.repoPath.trim();
        if (!repoPath) {
          console.warn("[vulndash.feed.invalid]", { id: config.id, type: config.type, reason: "missing_repo_path" });
          break;
        }
        feeds.push(new GitHubRepoClient(httpClient, config.id, config.name, config.token ?? "", repoPath, controls));
        break;
      }
      case FEED_TYPES.GENERIC_JSON: {
        const url = config.url.trim();
        if (!url) {
          console.warn("[vulndash.feed.invalid]", { id: config.id, type: config.type, reason: "missing_url" });
          break;
        }
        feeds.push(new GenericJsonFeedClient(
          httpClient,
          config.id,
          config.name,
          url,
          config.token ?? "",
          config.authHeaderName ?? "Authorization",
          controls
        ));
        break;
      }
      case FEED_TYPES.OSV: {
        if (!dependencies.osvQueryCache || !dependencies.getPurls) {
          console.warn("[vulndash.feed.invalid]", { id: config.id, type: config.type, reason: "missing_osv_dependencies" });
          break;
        }
        feeds.push(new OsvFeedClient(
          httpClient,
          dependencies.osvQueryCache,
          dependencies.getPurls,
          controls,
          config
        ));
        break;
      }
      default: {
        const unreachable = config;
        console.warn("[vulndash.feed.unknown]", unreachable);
      }
    }
  }
  return feeds;
};

// src/infrastructure/clients/common/HttpClient.ts
var parseRetryAfterMs = (retryAfterHeader) => {
  if (!retryAfterHeader) return void 0;
  const seconds = Number(retryAfterHeader);
  if (!Number.isNaN(seconds) && Number.isFinite(seconds) && seconds > 0) {
    return seconds * 1e3;
  }
  const retryDate = Date.parse(retryAfterHeader);
  if (Number.isNaN(retryDate)) return void 0;
  return Math.max(retryDate - Date.now(), 0);
};
var toAbortMetadata = (url) => ({ url });
var throwIfAborted = (signal, url) => {
  if (signal.aborted) {
    throw new RetryableNetworkError("Request aborted before execution", toAbortMetadata(url));
  }
};
var waitForAbort = (signal, url) => new Promise((_, reject) => {
  const onAbort = () => {
    signal.removeEventListener("abort", onAbort);
    reject(new RetryableNetworkError("Request aborted during execution", toAbortMetadata(url)));
  };
  signal.addEventListener("abort", onAbort, { once: true });
});
var executeWithAbort = async (url, signal, action) => {
  throwIfAborted(signal, url);
  return Promise.race([
    action(),
    waitForAbort(signal, url)
  ]);
};
var normalizeHeaders = (headers) => Object.fromEntries(
  Object.entries(headers ?? {}).map(([key, value]) => [key.toLowerCase(), String(value)])
);
var buildHttpErrorMetadata = (status, headers, url) => {
  const retryAfterMs = parseRetryAfterMs(headers["retry-after"]);
  return {
    status,
    headers,
    url,
    ...retryAfterMs !== void 0 ? { retryAfterMs } : {}
  };
};
var handleResponse = (url, response) => {
  const normalizedHeaders = normalizeHeaders(response.headers);
  if (response.status >= 200 && response.status < 300) {
    return { data: response.json, status: response.status, headers: normalizedHeaders };
  }
  const metadata = buildHttpErrorMetadata(response.status, normalizedHeaders, url);
  if (response.status === 429) {
    throw new RateLimitHttpError(`Rate limited while requesting ${url}`, metadata);
  }
  if (response.status >= 500) {
    throw new ServerHttpError(`HTTP ${response.status} for ${url}`, metadata);
  }
  throw new ClientHttpError(`HTTP ${response.status} for ${url}`, metadata);
};
var normalizeRequestFailure = (error, url) => {
  if (error instanceof ClientHttpError || error instanceof ServerHttpError || error instanceof RateLimitHttpError || error instanceof RetryableNetworkError) {
    throw error;
  }
  const message = error instanceof Error ? error.message : "Unknown network error";
  if (message.toLowerCase().includes("timeout")) {
    throw new TimeoutHttpError(`Timeout requesting ${url}`, { url });
  }
  throw new RetryableNetworkError(`Network request failed for ${url}`, { url });
};
var HttpClient = class {
  async getJson(url, headers, signal) {
    try {
      const response = await executeWithAbort(url, signal, async () => requestUrl({
        url,
        method: "GET",
        headers,
        throw: false
      }));
      return handleResponse(url, response);
    } catch (error) {
      return normalizeRequestFailure(error, url);
    }
  }
  async postJson(url, body, headers, signal) {
    try {
      const response = await executeWithAbort(url, signal, async () => requestUrl({
        url,
        method: "POST",
        headers,
        body: JSON.stringify(body),
        contentType: "application/json",
        throw: false
      }));
      return handleResponse(url, response);
    } catch (error) {
      return normalizeRequestFailure(error, url);
    }
  }
};

// src/infrastructure/obsidian/ProjectNoteLookupService.ts
var compareProjectNoteOptions = (left, right) => left.displayName.localeCompare(right.displayName) || left.notePath.localeCompare(right.notePath);
var getFallbackDisplayName = (notePath, displayName) => {
  const normalizedDisplayName = displayName?.trim();
  if (normalizedDisplayName) {
    return normalizedDisplayName;
  }
  const segments = normalizePath(notePath).split("/").filter(Boolean);
  const filename = segments.at(-1) ?? notePath;
  return filename.replace(/\.md$/i, "") || notePath;
};
var ProjectNoteLookupService = class {
  constructor(vault) {
    this.vault = vault;
  }
  async getByPaths(references) {
    const resolved = /* @__PURE__ */ new Map();
    for (const reference of references) {
      const noteState = await this.resolveByPath(reference.notePath, reference.displayName);
      resolved.set(noteState.notePath, noteState);
    }
    return resolved;
  }
  listProjectNotes() {
    return this.vault.getMarkdownFiles().map((file) => ({
      displayName: file.basename,
      notePath: normalizePath(file.path)
    })).sort(compareProjectNoteOptions);
  }
  async resolveByPath(notePath, displayName) {
    const normalizedPath = normalizePath(notePath.trim());
    const target = this.vault.getAbstractFileByPath(normalizedPath);
    if (target instanceof TFile) {
      return {
        displayName: target.basename,
        notePath: normalizePath(target.path),
        status: "linked"
      };
    }
    return {
      displayName: getFallbackDisplayName(normalizedPath, displayName),
      notePath: normalizedPath,
      status: "broken"
    };
  }
};

// src/domain/correlation/ProjectNoteReference.ts
var normalizeProjectNotePathValue = (value) => value.trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.?\//, "");
var normalizeProjectNotePath = (value) => normalizeProjectNotePathValue(value);
var createProjectNoteReference = (notePath, displayName) => {
  const normalizedPath = normalizeProjectNotePathValue(notePath);
  if (!normalizedPath) {
    throw new Error("Project note path is required.");
  }
  const normalizedDisplayName = displayName?.trim();
  if (!normalizedDisplayName) {
    return {
      notePath: normalizedPath
    };
  }
  return {
    displayName: normalizedDisplayName,
    notePath: normalizedPath
  };
};

// src/domain/correlation/SbomProjectMapping.ts
var createSbomProjectMapping = (sbomId, projectNote) => {
  const normalizedSbomId = sbomId.trim();
  if (!normalizedSbomId) {
    throw new Error("SBOM identifier is required.");
  }
  return {
    projectNote,
    sbomId: normalizedSbomId
  };
};

// src/infrastructure/storage/SbomProjectMappingRepository.ts
var SbomProjectMappingRepository = class {
  constructor(getSboms, updateSbomConfig) {
    this.getSboms = getSboms;
    this.updateSbomConfig = updateSbomConfig;
  }
  async deleteBySbomId(sbomId) {
    await this.updateSbomConfig(sbomId, {
      linkedProjectDisplayName: "",
      linkedProjectNotePath: ""
    });
  }
  async getBySbomId(sbomId) {
    const sbom = this.getSboms().find((entry) => entry.id === sbomId);
    if (!sbom || !sbom.linkedProjectNotePath) {
      return null;
    }
    return createSbomProjectMapping(
      sbom.id,
      createProjectNoteReference(sbom.linkedProjectNotePath, sbom.linkedProjectDisplayName)
    );
  }
  async list() {
    return this.getSboms().flatMap((sbom) => {
      if (!sbom.linkedProjectNotePath) {
        return [];
      }
      return [createSbomProjectMapping(
        sbom.id,
        createProjectNoteReference(sbom.linkedProjectNotePath, sbom.linkedProjectDisplayName)
      )];
    });
  }
  async replaceNotePath(oldNotePath, nextProjectNote) {
    const normalizedOldPath = normalizeProjectNotePath(oldNotePath);
    const matchingSboms = this.getSboms().filter((sbom) => normalizeProjectNotePath(sbom.linkedProjectNotePath ?? "") === normalizedOldPath);
    for (const sbom of matchingSboms) {
      await this.save(createSbomProjectMapping(sbom.id, nextProjectNote));
    }
    return matchingSboms.length;
  }
  async save(mapping) {
    await this.updateSbomConfig(mapping.sbomId, {
      linkedProjectDisplayName: mapping.projectNote.displayName ?? "",
      linkedProjectNotePath: mapping.projectNote.notePath
    });
  }
};

// src/domain/rollup/DailyRollupPolicy.ts
var DailyRollupPolicy = class {
  constructor(props) {
    this.excludedTriageStates = new Set(props.excludedTriageStates);
    this.includeUnmappedFindings = props.includeUnmappedFindings;
    this.severityThreshold = props.severityThreshold;
  }
  shouldInclude(input) {
    if (severityOrder[input.severity] < severityOrder[this.severityThreshold]) {
      return false;
    }
    if (this.excludedTriageStates.has(input.triageState)) {
      return false;
    }
    if (input.resolution.affectedProjects.length > 0) {
      return true;
    }
    return this.includeUnmappedFindings && input.resolution.unmappedSboms.length > 0;
  }
  toJSON() {
    return {
      excludedTriageStates: Array.from(this.excludedTriageStates),
      includeUnmappedFindings: this.includeUnmappedFindings,
      severityThreshold: this.severityThreshold
    };
  }
};

// src/application/rollup/DailyRollupGenerator.ts
var DailyRollupGenerator = class {
  constructor(selectFindings, renderer, writer) {
    this.selectFindings = selectFindings;
    this.renderer = renderer;
    this.writer = writer;
  }
  async execute(input) {
    const findings = this.selectFindings.execute({
      affectedProjectsByVulnerabilityRef: input.affectedProjectsByVulnerabilityRef,
      policy: new DailyRollupPolicy({
        excludedTriageStates: input.settings.excludedTriageStates,
        includeUnmappedFindings: input.settings.includeUnmappedFindings,
        severityThreshold: input.settings.severityThreshold
      }),
      triageByCacheKey: input.triageByCacheKey,
      vulnerabilities: input.vulnerabilities
    });
    const document = this.renderer.render({
      date: input.date,
      findings
    });
    const written = await this.writer.write({
      date: input.date,
      document,
      folderPath: input.settings.folderPath
    });
    return {
      content: written.content,
      date: input.date,
      findingsCount: findings.length,
      path: written.path
    };
  }
};

// src/application/rollup/SelectRollupFindings.ts
var compareFindings = (left, right) => severityOrder[right.vulnerability.severity] - severityOrder[left.vulnerability.severity] || right.vulnerability.updatedAt.localeCompare(left.vulnerability.updatedAt) || right.vulnerability.publishedAt.localeCompare(left.vulnerability.publishedAt) || left.vulnerability.source.localeCompare(right.vulnerability.source) || left.vulnerability.id.localeCompare(right.vulnerability.id);
var SelectRollupFindings = class {
  constructor(relationshipNormalizer = new RelationshipNormalizer()) {
    this.relationshipNormalizer = relationshipNormalizer;
  }
  execute(input) {
    const findingsByKey = /* @__PURE__ */ new Map();
    for (const vulnerability of input.vulnerabilities) {
      const key = buildVulnerabilityCacheKey(vulnerability);
      if (findingsByKey.has(key)) {
        continue;
      }
      const triage = input.triageByCacheKey.get(key) ?? {
        record: null,
        state: DEFAULT_TRIAGE_STATE
      };
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
      const resolution = input.affectedProjectsByVulnerabilityRef.get(vulnerabilityRef) ?? {
        affectedProjects: [],
        unmappedSboms: []
      };
      if (!input.policy.shouldInclude({
        resolution,
        severity: vulnerability.severity,
        triageState: triage.state
      })) {
        continue;
      }
      findingsByKey.set(key, {
        affectedProjects: resolution.affectedProjects,
        key,
        triageRecord: triage.record,
        triageState: triage.state,
        unmappedSboms: resolution.unmappedSboms,
        vulnerability
      });
    }
    return Array.from(findingsByKey.values()).sort(compareFindings);
  }
};

// src/infrastructure/obsidian/MarkdownBuilder.ts
var MarkdownBuilder = class _MarkdownBuilder {
  constructor() {
    this.lines = [];
  }
  h1(text) {
    return this.heading(1, text);
  }
  h2(text) {
    return this.heading(2, text);
  }
  h3(text) {
    return this.heading(3, text);
  }
  h4(text) {
    return this.heading(4, text);
  }
  h5(text) {
    return this.heading(5, text);
  }
  h6(text) {
    return this.heading(6, text);
  }
  heading(level, text) {
    const normalized = this.normalizeInline(text);
    if (!normalized) {
      return this;
    }
    this.ensureBlockSeparation();
    this.lines.push(`${"#".repeat(level)} ${normalized}`);
    this.lines.push("");
    return this;
  }
  paragraph(text) {
    const normalizedLines = this.normalizeMultiline(text).filter((line) => line.trim().length > 0);
    if (normalizedLines.length === 0) {
      return this;
    }
    this.ensureBlockSeparation();
    this.lines.push(...normalizedLines);
    this.lines.push("");
    return this;
  }
  line(text) {
    const normalized = this.normalizeInline(text);
    if (!normalized) {
      return this;
    }
    this.lines.push(normalized);
    return this;
  }
  raw(text) {
    const normalizedLines = this.normalizeMultiline(text);
    if (normalizedLines.length === 0) {
      return this;
    }
    this.lines.push(...normalizedLines);
    return this;
  }
  emptyLine() {
    if (this.lines.length === 0 || this.lines[this.lines.length - 1] === "") {
      return this;
    }
    this.lines.push("");
    return this;
  }
  callout(type, title, contentLines = []) {
    const normalizedTitle = this.normalizeInline(title);
    const normalizedContent = contentLines.flatMap((line) => this.normalizeMultiline(line)).filter((line) => line.trim().length > 0);
    this.ensureBlockSeparation();
    this.lines.push(`> [!${type}]${normalizedTitle ? ` ${normalizedTitle}` : ""}`);
    if (normalizedContent.length === 0) {
      this.lines.push("> ");
    } else {
      for (const line of normalizedContent) {
        this.lines.push(`> ${line}`);
      }
    }
    this.lines.push("");
    return this;
  }
  blockquote(text) {
    const normalizedLines = Array.isArray(text) ? text.flatMap((line) => this.normalizeMultiline(line)) : this.normalizeMultiline(text);
    const content = normalizedLines.filter((line) => line.trim().length > 0);
    if (content.length === 0) {
      return this;
    }
    this.ensureBlockSeparation();
    for (const line of content) {
      this.lines.push(`> ${line}`);
    }
    this.lines.push("");
    return this;
  }
  unorderedList(items) {
    const normalizedItems = items.filter((item) => typeof item === "string").flatMap((item) => this.normalizeMultiline(item)).map((item) => item.trim()).filter((item) => item.length > 0);
    if (normalizedItems.length === 0) {
      return this;
    }
    this.ensureBlockSeparation();
    for (const item of normalizedItems) {
      this.lines.push(`- ${item}`);
    }
    this.lines.push("");
    return this;
  }
  orderedList(items, startAt = 1) {
    const normalizedItems = items.filter((item) => typeof item === "string").flatMap((item) => this.normalizeMultiline(item)).map((item) => item.trim()).filter((item) => item.length > 0);
    if (normalizedItems.length === 0) {
      return this;
    }
    this.ensureBlockSeparation();
    let index = startAt;
    for (const item of normalizedItems) {
      this.lines.push(`${index}. ${item}`);
      index += 1;
    }
    this.lines.push("");
    return this;
  }
  definitionList(items) {
    const normalizedItems = items.map((item) => ({
      term: this.normalizeInline(item.term),
      description: this.normalizeInline(item.description)
    })).filter((item) => item.term.length > 0 && item.description.length > 0);
    if (normalizedItems.length === 0) {
      return this;
    }
    this.ensureBlockSeparation();
    for (const item of normalizedItems) {
      this.lines.push(
        `- **${_MarkdownBuilder.escapeInline(item.term)}:** ${item.description}`
      );
    }
    this.lines.push("");
    return this;
  }
  table(table) {
    const headers = table.headers.map((header) => this.escapeTableCell(this.normalizeInline(header)));
    if (headers.length === 0) {
      return this;
    }
    const rows = table.rows.map((row) => {
      const padded = [...row];
      while (padded.length < headers.length) {
        padded.push("");
      }
      return padded.slice(0, headers.length).map((cell) => this.escapeTableCell(this.stringifyCell(cell)));
    });
    this.ensureBlockSeparation();
    this.lines.push(`| ${headers.join(" | ")} |`);
    this.lines.push(`| ${headers.map(() => "---").join(" | ")} |`);
    for (const row of rows) {
      this.lines.push(`| ${row.join(" | ")} |`);
    }
    this.lines.push("");
    return this;
  }
  codeFence(code, language) {
    const normalizedCode = code.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const safeLanguage = this.normalizeFenceLanguage(language);
    this.ensureBlockSeparation();
    this.lines.push(`\`\`\`${safeLanguage}`);
    this.lines.push(...normalizedCode.split("\n"));
    this.lines.push("```");
    this.lines.push("");
    return this;
  }
  horizontalRule() {
    this.ensureBlockSeparation();
    this.lines.push("---");
    this.lines.push("");
    return this;
  }
  appendIf(condition, fn) {
    if (condition) {
      fn(this);
    }
    return this;
  }
  append(builder) {
    const built = builder.build();
    if (!built) {
      return this;
    }
    this.ensureBlockSeparation();
    this.lines.push(...built.split("\n"));
    return this;
  }
  build() {
    return this.lines.join("\n").trimEnd();
  }
  static bold(text) {
    return `**${_MarkdownBuilder.escapeInline(text)}**`;
  }
  static italic(text) {
    return `*${_MarkdownBuilder.escapeInline(text)}*`;
  }
  static strikethrough(text) {
    return `~~${_MarkdownBuilder.escapeInline(text)}~~`;
  }
  static inlineCode(text) {
    const normalized = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    const escaped = normalized.replace(/`/g, "\\`");
    return `\`${escaped}\``;
  }
  static link(label, url, title) {
    const safeLabel = _MarkdownBuilder.escapeInline(label.trim());
    const safeUrl = _MarkdownBuilder.sanitizeUrl(url);
    const safeTitle = title?.trim() ? ` "${title.replace(/"/g, "&quot;")}"` : "";
    if (!safeLabel || !safeUrl) {
      return safeLabel || "";
    }
    return `[${safeLabel}](${safeUrl}${safeTitle})`;
  }
  ensureBlockSeparation() {
    if (this.lines.length === 0) {
      return;
    }
    if (this.lines[this.lines.length - 1] !== "") {
      this.lines.push("");
    }
  }
  normalizeInline(text) {
    return _MarkdownBuilder.normalizeInlineStatic(text);
  }
  normalizeMultiline(text) {
    return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").map((line) => line.trimEnd());
  }
  stringifyCell(value) {
    if (value === null || value === void 0) {
      return "";
    }
    if (typeof value === "boolean") {
      return value ? "Yes" : "No";
    }
    return this.normalizeInline(String(value));
  }
  escapeTableCell(value) {
    return value.replace(/\|/g, "\\|");
  }
  normalizeFenceLanguage(language) {
    if (!language) {
      return "";
    }
    return language.trim().replace(/[^\w+-]/g, "");
  }
  static normalizeInlineStatic(text) {
    return text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n+/g, " ").trim();
  }
  static escapeInline(text) {
    return text.replace(/[\\`*_{}[\]()#+.!-]/g, "\\$&");
  }
  static sanitizeUrl(url) {
    const trimmed = url.trim();
    if (!trimmed) {
      return "";
    }
    try {
      const parsed = new URL(trimmed);
      if (!["http:", "https:", "mailto:"].includes(parsed.protocol)) {
        return "";
      }
      return parsed.toString();
    } catch {
      return "";
    }
  }
};

// src/infrastructure/obsidian/WikiLinkFormatter.ts
var normalizeWikiLinkValue = (value) => value.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n+/g, " ").replace(/[[\]#^|]/g, "").replace(/\s+/g, " ").trim();
var normalizeNotePath = (value) => value.trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.?\//, "").replace(/\.md$/i, "");
var WikiLinkFormatter = class {
  format(notePath, displayName) {
    const normalizedPath = this.normalizeTarget(notePath);
    const normalizedDisplayName = this.normalizeDisplayName(displayName ?? "");
    if (!normalizedPath) {
      return normalizedDisplayName ? `[[${normalizedDisplayName}]]` : "";
    }
    const defaultDisplayName = normalizedPath.split("/").at(-1) ?? normalizedPath;
    if (!normalizedDisplayName || normalizedDisplayName === defaultDisplayName) {
      return `[[${normalizedPath}]]`;
    }
    return `[[${normalizedPath}|${normalizedDisplayName}]]`;
  }
  formatParts(parts) {
    return this.format(parts.target, parts.displayName);
  }
  normalizeTarget(notePath) {
    return normalizeWikiLinkValue(normalizeNotePath(notePath));
  }
  normalizeDisplayName(displayName) {
    return normalizeWikiLinkValue(displayName);
  }
};

// src/application/markdown/LinkResolver.ts
var LinkResolver = class {
  note(target, displayName) {
    const normalizedTarget = this.normalizeRequiredValue(target);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);
    return {
      target: normalizedTarget,
      ...normalizedDisplayName ? { displayName: normalizedDisplayName } : {}
    };
  }
  vulnerability(cveId, displayName) {
    const normalizedTarget = this.normalizeRequiredValue(cveId);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);
    return {
      target: normalizedTarget,
      ...normalizedDisplayName ? { displayName: normalizedDisplayName } : {}
    };
  }
  advisory(ghsaId, displayName) {
    const normalizedTarget = this.normalizeRequiredValue(ghsaId);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);
    return {
      target: normalizedTarget,
      ...normalizedDisplayName ? { displayName: normalizedDisplayName } : {}
    };
  }
  project(projectName, displayName) {
    const normalizedTarget = this.normalizeRequiredValue(projectName);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);
    return {
      target: normalizedTarget,
      ...normalizedDisplayName ? { displayName: normalizedDisplayName } : {}
    };
  }
  component(input) {
    const normalizedName = this.normalizeRequiredValue(input.name);
    const normalizedVersion = this.normalizeOptionalValue(input.version);
    const normalizedDisplayName = this.normalizeOptionalValue(input.displayName);
    const includeVersionInTarget = input.includeVersionInTarget ?? true;
    const target = includeVersionInTarget && normalizedVersion ? `${normalizedName} ${normalizedVersion}` : normalizedName;
    return {
      target,
      ...normalizedDisplayName ? { displayName: normalizedDisplayName } : {}
    };
  }
  packageVersion(packageName, version, displayName) {
    const normalizedPackageName = this.normalizeRequiredValue(packageName);
    const normalizedVersion = this.normalizeOptionalValue(version);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);
    const target = normalizedVersion ? `${normalizedPackageName}@${normalizedVersion}` : normalizedPackageName;
    return {
      target,
      ...normalizedDisplayName ? { displayName: normalizedDisplayName } : {}
    };
  }
  normalizeRequiredValue(value) {
    return this.normalizeValue(value);
  }
  normalizeValue(value) {
    return value.replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/\n+/g, " ").replace(/\s+/g, " ").trim();
  }
  normalizeOptionalValue(value) {
    if (typeof value !== "string") {
      return void 0;
    }
    const normalized = this.normalizeValue(value);
    return normalized.length > 0 ? normalized : void 0;
  }
};

// src/application/markdown/VulnerabilityMarkdownSupport.ts
var VulnerabilityMarkdownSupport = class {
  constructor(linkResolver = new LinkResolver(), wikiLinkFormatter = new WikiLinkFormatter()) {
    this.linkResolver = linkResolver;
    this.wikiLinkFormatter = wikiLinkFormatter;
  }
  getPrimaryIdentifier(vulnerability) {
    return vulnerability.metadata?.cveId ?? vulnerability.metadata?.ghsaId ?? vulnerability.metadata?.identifiers?.[0] ?? vulnerability.metadata?.aliases?.[0];
  }
  formatVulnerabilityLink(vulnerability, displayName) {
    const identifier = this.getPrimaryIdentifier(vulnerability) ?? vulnerability.id;
    const resolved = this.linkResolver.vulnerability(identifier, displayName ?? identifier);
    return this.wikiLinkFormatter.format(resolved.target, resolved.displayName);
  }
  formatProjectLink(projectName, displayName) {
    const resolved = this.linkResolver.project(projectName, displayName);
    return this.wikiLinkFormatter.format(resolved.target, resolved.displayName);
  }
  formatComponentLink(name, version, displayName) {
    const normalizedVersion = version?.trim();
    const normalizedDisplayName = displayName?.trim();
    const resolved = this.linkResolver.component({
      name,
      ...normalizedVersion ? { version: normalizedVersion } : {},
      displayName: normalizedDisplayName || (normalizedVersion ? `${name} ${normalizedVersion}` : name),
      includeVersionInTarget: true
    });
    return this.wikiLinkFormatter.format(resolved.target, resolved.displayName);
  }
  buildIdentifierLines(vulnerability) {
    const lines = [];
    if (vulnerability.metadata?.cveId) {
      lines.push(
        `CVE: ${this.wikiLinkFormatter.format(
          this.linkResolver.vulnerability(vulnerability.metadata.cveId).target
        )}`
      );
    }
    if (vulnerability.metadata?.ghsaId) {
      lines.push(
        `GHSA: ${this.wikiLinkFormatter.format(
          this.linkResolver.advisory(vulnerability.metadata.ghsaId).target
        )}`
      );
    }
    if (vulnerability.metadata?.aliases?.length) {
      lines.push(`Aliases: ${vulnerability.metadata.aliases.join(", ")}`);
    }
    return lines;
  }
  buildAffectedProjectLine(affectedProjects) {
    const projectLinks = affectedProjects.filter((project) => project.trim().length > 0).map((project) => this.formatProjectLink(project)).filter((link) => link.length > 0);
    if (projectLinks.length === 0) {
      return [];
    }
    return [`Affected Projects: ${projectLinks.join(", ")}`];
  }
  buildMetadataItems(vulnerability) {
    const items = [];
    items.push({ term: "Source", description: vulnerability.source });
    items.push({ term: "Published", description: vulnerability.publishedAt });
    items.push({ term: "Updated", description: vulnerability.updatedAt });
    if (Number.isFinite(vulnerability.cvssScore)) {
      items.push({ term: "CVSS Score", description: String(vulnerability.cvssScore) });
    }
    if (vulnerability.metadata?.cwes?.length) {
      items.push({ term: "CWEs", description: vulnerability.metadata.cwes.join(", ") });
    }
    if (vulnerability.metadata?.vendors?.length) {
      items.push({ term: "Vendors", description: vulnerability.metadata.vendors.join(", ") });
    }
    if (vulnerability.metadata?.identifiers?.length) {
      items.push({ term: "Identifiers", description: vulnerability.metadata.identifiers.join(", ") });
    }
    if (vulnerability.metadata?.vulnerableVersionRanges?.length) {
      items.push({
        term: "Vulnerable Ranges",
        description: vulnerability.metadata.vulnerableVersionRanges.join(", ")
      });
    }
    if (vulnerability.metadata?.firstPatchedVersions?.length) {
      items.push({
        term: "First Patched Versions",
        description: vulnerability.metadata.firstPatchedVersions.join(", ")
      });
    }
    if (vulnerability.metadata?.vulnerableFunctions?.length) {
      items.push({
        term: "Vulnerable Functions",
        description: vulnerability.metadata.vulnerableFunctions.join(", ")
      });
    }
    return items;
  }
  buildAffectedPackageTableRows(vulnerability) {
    return (vulnerability.metadata?.affectedPackages ?? []).filter((pkg) => pkg.name.trim().length > 0).map((pkg) => ({
      packageLink: this.formatAffectedPackageLink(pkg),
      ecosystem: pkg.ecosystem ?? "Unknown",
      vulnerableVersionRange: pkg.vulnerableVersionRange ?? "Unknown",
      firstPatchedVersion: pkg.firstPatchedVersion ?? "Unknown",
      vendor: pkg.vendor ?? "Unknown"
    }));
  }
  buildAffectedPackageDetailItems(affectedPackage) {
    const items = [];
    if (affectedPackage.ecosystem) {
      items.push({ term: "Ecosystem", description: affectedPackage.ecosystem });
    }
    if (affectedPackage.vendor) {
      items.push({ term: "Vendor", description: affectedPackage.vendor });
    }
    if (affectedPackage.version) {
      items.push({
        term: "Version",
        description: MarkdownBuilder.inlineCode(affectedPackage.version)
      });
    }
    if (affectedPackage.vulnerableVersionRange) {
      items.push({
        term: "Vulnerable Range",
        description: affectedPackage.vulnerableVersionRange
      });
    }
    if (affectedPackage.firstPatchedVersion) {
      items.push({
        term: "First Patched Version",
        description: affectedPackage.firstPatchedVersion
      });
    }
    if (affectedPackage.purl) {
      items.push({
        term: "PURL",
        description: MarkdownBuilder.inlineCode(affectedPackage.purl)
      });
    }
    if (affectedPackage.cpe) {
      items.push({
        term: "CPE",
        description: MarkdownBuilder.inlineCode(affectedPackage.cpe)
      });
    }
    if (affectedPackage.sourceCodeLocation) {
      items.push({
        term: "Source Code",
        description: MarkdownBuilder.link(
          affectedPackage.sourceCodeLocation,
          affectedPackage.sourceCodeLocation
        )
      });
    }
    if (affectedPackage.vulnerableFunctions?.length) {
      items.push({
        term: "Vulnerable Functions",
        description: affectedPackage.vulnerableFunctions.join(", ")
      });
    }
    return items;
  }
  buildReferenceLinks(vulnerability) {
    const baseReferences = vulnerability.references.filter((reference) => reference.trim().length > 0).map((reference) => MarkdownBuilder.link(reference, reference));
    const sourceUrls = vulnerability.metadata?.sourceUrls;
    if (!sourceUrls) {
      return baseReferences;
    }
    const additionalReferences = [
      sourceUrls.api,
      sourceUrls.html,
      sourceUrls.repositoryAdvisory,
      sourceUrls.sourceCode
    ].filter((url) => typeof url === "string" && url.trim().length > 0).map((url) => MarkdownBuilder.link(url, url));
    return [...baseReferences, ...additionalReferences];
  }
  severityWeight(severity) {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return 5;
      case "HIGH":
        return 4;
      case "MEDIUM":
        return 3;
      case "LOW":
        return 2;
      case "UNKNOWN":
      default:
        return 1;
    }
  }
  compareSeverity(left, right) {
    return this.severityWeight(right) - this.severityWeight(left);
  }
  getSeverityCalloutType(severity) {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "danger";
      case "HIGH":
        return "warning";
      case "MEDIUM":
        return "info";
      case "LOW":
      case "UNKNOWN":
      default:
        return "success";
    }
  }
  formatAffectedPackageLink(affectedPackage) {
    return this.formatComponentLink(
      affectedPackage.name,
      affectedPackage.version,
      affectedPackage.version ? `${affectedPackage.name} ${affectedPackage.version}` : affectedPackage.name
    );
  }
};

// src/application/markdown/DailyRollupMarkdownComposer.ts
var DailyRollupMarkdownComposer = class {
  constructor(support = new VulnerabilityMarkdownSupport()) {
    this.support = support;
  }
  compose(input) {
    const builder = new MarkdownBuilder();
    const title = input.title?.trim() || `Daily Rollup - ${input.dateLabel}`;
    const sortedFindings = [...input.findings].sort((left, right) => {
      const severityCompare = this.support.compareSeverity(
        String(left.vulnerability.severity),
        String(right.vulnerability.severity)
      );
      if (severityCompare !== 0) {
        return severityCompare;
      }
      return left.vulnerability.updatedAt.localeCompare(right.vulnerability.updatedAt) * -1;
    });
    builder.h1(title);
    builder.callout("summary", "Rollup Summary", [
      `Generated At: ${input.generatedAt}`,
      `Findings: ${MarkdownBuilder.bold(String(sortedFindings.length))}`,
      `Critical / High: ${MarkdownBuilder.bold(String(this.countCriticalHigh(sortedFindings)))}`
    ]);
    if (input.summary?.trim()) {
      builder.paragraph(input.summary.trim());
    }
    if (sortedFindings.length === 0) {
      builder.callout("success", "No Findings Selected", [
        "No findings met the current rollup selection criteria."
      ]);
      return builder.build();
    }
    builder.h2("Findings Overview");
    builder.table({
      headers: ["Severity", "Identifier", "Title", "Projects", "Components"],
      rows: sortedFindings.map((finding) => [
        finding.vulnerability.severity,
        this.support.formatVulnerabilityLink(
          finding.vulnerability,
          this.support.getPrimaryIdentifier(finding.vulnerability)
        ),
        finding.vulnerability.title,
        this.formatProjectSummary(finding.affectedProjects),
        this.formatComponentSummary(finding.matchedComponents)
      ])
    });
    builder.h2("Detailed Findings");
    for (const finding of sortedFindings) {
      const vulnerability = finding.vulnerability;
      const identifier = this.support.getPrimaryIdentifier(vulnerability) ?? vulnerability.id;
      builder.h3(identifier);
      builder.callout(
        this.support.getSeverityCalloutType(String(vulnerability.severity)),
        "Finding Summary",
        [
          `Severity: ${MarkdownBuilder.bold(String(vulnerability.severity))}`,
          `Title: ${vulnerability.title}`,
          `Published: ${vulnerability.publishedAt}`,
          `Updated: ${vulnerability.updatedAt}`,
          ...finding.triageState ? [`Triage: ${finding.triageState}`] : []
        ]
      );
      if (vulnerability.summary.trim()) {
        builder.paragraph(vulnerability.summary.trim());
      }
      const metadata = this.support.buildMetadataItems(vulnerability);
      if (metadata.length > 0) {
        builder.definitionList(metadata);
      }
      if (finding.rationale?.trim()) {
        builder.h4("Selection Rationale");
        builder.paragraph(finding.rationale.trim());
      }
      const projectLinks = this.buildProjectLinks(finding.affectedProjects);
      if (projectLinks.length > 0) {
        builder.h4("Affected Projects");
        builder.unorderedList(projectLinks);
      }
      const componentLinks = this.buildComponentLinks(finding.matchedComponents);
      if (componentLinks.length > 0) {
        builder.h4("Matched Components");
        builder.unorderedList(componentLinks);
      }
      const packageRows = this.support.buildAffectedPackageTableRows(vulnerability);
      if (packageRows.length > 0) {
        builder.h4("Affected Packages");
        builder.table({
          headers: ["Package", "Ecosystem", "Vulnerable Range", "First Patched", "Vendor"],
          rows: packageRows.map((row) => [
            row.packageLink,
            row.ecosystem,
            row.vulnerableVersionRange,
            row.firstPatchedVersion,
            row.vendor
          ])
        });
      }
      const references = this.support.buildReferenceLinks(vulnerability);
      if (references.length > 0) {
        builder.h4("References");
        builder.unorderedList(references);
      }
    }
    return builder.build();
  }
  buildProjectLinks(projects) {
    if (!projects?.length) {
      return [];
    }
    return projects.map(
      (project) => this.support.formatProjectLink(project.target, project.displayName)
    ).filter((link) => link.length > 0);
  }
  buildComponentLinks(components) {
    if (!components?.length) {
      return [];
    }
    return components.filter((component) => component.name.trim().length > 0).map((component) => {
      const wikiLink = this.support.formatComponentLink(
        component.name,
        component.version,
        component.version ? `${component.name} ${component.version}` : component.name
      );
      return component.ecosystem ? `${wikiLink} (${component.ecosystem})` : wikiLink;
    });
  }
  formatProjectSummary(projects) {
    if (!projects?.length) {
      return "None";
    }
    const seen = /* @__PURE__ */ new Set();
    const values = [];
    for (const project of projects) {
      const value = project.displayName?.trim() || project.target.trim();
      if (!value || seen.has(value)) {
        continue;
      }
      seen.add(value);
      values.push(value);
    }
    return values.join(", ") || "None";
  }
  formatComponentSummary(components) {
    if (!components?.length) {
      return "None";
    }
    const values = components.filter((component) => component.name.trim().length > 0).map((component) => component.version ? `${component.name} ${component.version}` : component.name);
    return values.join(", ") || "None";
  }
  countCriticalHigh(findings) {
    return findings.filter((finding) => {
      const severity = String(finding.vulnerability.severity).toUpperCase();
      return severity === "CRITICAL" || severity === "HIGH";
    }).length;
  }
};

// src/application/rollup/RollupMarkdownRenderer.ts
var asSentence = (value) => {
  const normalized = value.trim();
  if (!normalized) {
    return "";
  }
  return /[.!?]$/.test(normalized) ? normalized : `${normalized}.`;
};
var truncateInline = (value, maxLength = 180) => {
  const normalized = value.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }
  return `${normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd()}\u2026`;
};
var safeInline = (value, fallback = "Not provided") => {
  const normalized = value?.replace(/\s+/g, " ").trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
};
var RollupMarkdownRenderer = class {
  constructor(composer = new DailyRollupMarkdownComposer()) {
    this.composer = composer;
  }
  render(input) {
    const composerInput = this.mapToComposerInput(input.date, input.findings);
    const composedMarkdown = this.composer.compose(composerInput);
    const title = `# ${composerInput.title ?? `Daily Rollup - ${input.date}`}`;
    const body = this.stripLeadingTitleHeading(composedMarkdown, title);
    return {
      analystNotesHeading: "## Analyst Notes",
      analystNotesPlaceholder: "- Add analyst notes, escalation context, and follow-up decisions here.",
      managedSections: [
        {
          key: "daily-rollup",
          content: body
        }
      ],
      title
    };
  }
  mapToComposerInput(date, findings) {
    const sortedFindings = this.sortFindings(findings);
    return {
      generatedAt: date,
      dateLabel: date,
      title: `VulnDash Briefing ${date}`,
      summary: this.buildSummary(sortedFindings),
      findings: sortedFindings.map((finding) => this.mapFinding(finding))
    };
  }
  mapFinding(finding) {
    const matchedComponents = this.extractMatchedComponents(finding);
    return {
      vulnerability: finding.vulnerability,
      affectedProjects: finding.affectedProjects.map((project) => {
        const target = project.notePath.trim();
        const displayName = project.displayName?.trim();
        return {
          target,
          ...displayName ? { displayName } : {}
        };
      }).filter((project) => project.target.length > 0),
      triageState: formatTriageStateLabel(finding.triageState),
      rationale: this.buildFindingRationale(finding),
      ...matchedComponents ? { matchedComponents } : {}
    };
  }
  extractMatchedComponents(finding) {
    const affectedPackages = finding.vulnerability.metadata?.affectedPackages ?? [];
    if (affectedPackages.length === 0) {
      return void 0;
    }
    const seen = /* @__PURE__ */ new Set();
    const components = [];
    for (const pkg of affectedPackages) {
      const name = pkg.name?.trim();
      if (!name) {
        continue;
      }
      const version = pkg.version?.trim();
      const ecosystem = pkg.ecosystem?.trim();
      const key = `${name}::${version ?? ""}::${ecosystem ?? ""}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      components.push({
        name,
        ...version ? { version } : {},
        ...ecosystem ? { ecosystem } : {}
      });
    }
    return components.length > 0 ? components : void 0;
  }
  buildSummary(findings) {
    if (findings.length === 0) {
      return "No findings matched the daily briefing policy for this date.";
    }
    const uniqueProjectPaths = /* @__PURE__ */ new Set();
    let unmappedCount = 0;
    for (const finding of findings) {
      for (const project of finding.affectedProjects) {
        uniqueProjectPaths.add(project.notePath);
      }
      if (finding.unmappedSboms.length > 0) {
        unmappedCount += 1;
      }
    }
    const criticalCount = findings.filter(
      (finding) => safeInline(finding.vulnerability.severity, "UNKNOWN").toUpperCase() === "CRITICAL"
    ).length;
    const highCount = findings.filter(
      (finding) => safeInline(finding.vulnerability.severity, "UNKNOWN").toUpperCase() === "HIGH"
    ).length;
    const summaryParts = [
      `${findings.length} actionable finding${findings.length === 1 ? "" : "s"} matched the rollup policy`,
      `${uniqueProjectPaths.size} mapped project${uniqueProjectPaths.size === 1 ? "" : "s"} were impacted`,
      `${criticalCount} critical and ${highCount} high severit${highCount === 1 ? "y was" : "ies were"} identified`
    ];
    if (unmappedCount > 0) {
      summaryParts.push(
        `${unmappedCount} finding${unmappedCount === 1 ? "" : "s"} still require project mapping`
      );
    }
    return asSentence(summaryParts.join("; "));
  }
  buildFindingRationale(finding) {
    const parts = [
      `Included because severity is ${safeInline(finding.vulnerability.severity, "Unknown")}`,
      `and triage state is ${formatTriageStateLabel(finding.triageState)}`
    ];
    if (finding.affectedProjects.length > 0) {
      const projects = finding.affectedProjects.map((project) => project.displayName.trim()).filter((value) => value.length > 0);
      if (projects.length > 0) {
        parts.push(`mapped projects: ${projects.join(", ")}`);
      }
    }
    if (finding.unmappedSboms.length > 0) {
      const unmappedLabels = finding.unmappedSboms.map((sbom) => sbom.sbomLabel.trim()).filter((value) => value.length > 0);
      if (unmappedLabels.length > 0) {
        parts.push(`unmapped SBOMs: ${unmappedLabels.join(", ")}`);
      }
    }
    if (finding.triageRecord?.reason?.trim()) {
      parts.push(`analyst context: ${truncateInline(asSentence(finding.triageRecord.reason), 160)}`);
    }
    if (finding.triageRecord?.ticketRef?.trim()) {
      parts.push(`ticket: ${finding.triageRecord.ticketRef.trim()}`);
    }
    return asSentence(parts.join("; "));
  }
  stripLeadingTitleHeading(markdown, titleHeading) {
    const normalizedMarkdown = markdown.replace(/\r\n/g, "\n").trim();
    const normalizedTitleHeading = titleHeading.trim();
    if (!normalizedMarkdown.startsWith(normalizedTitleHeading)) {
      return normalizedMarkdown;
    }
    const stripped = normalizedMarkdown.slice(normalizedTitleHeading.length).replace(/^\n+/, "");
    return stripped.trim();
  }
  sortFindings(findings) {
    const severityWeight = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFORMATIONAL: 1,
      UNKNOWN: 0
    };
    return [...findings].sort((left, right) => {
      const leftSeverity = safeInline(left.vulnerability.severity, "UNKNOWN").toUpperCase();
      const rightSeverity = safeInline(right.vulnerability.severity, "UNKNOWN").toUpperCase();
      const severityDiff = (severityWeight[rightSeverity] ?? 0) - (severityWeight[leftSeverity] ?? 0);
      if (severityDiff !== 0) {
        return severityDiff;
      }
      const rightCvss = Number.isFinite(right.vulnerability.cvssScore) ? right.vulnerability.cvssScore : -1;
      const leftCvss = Number.isFinite(left.vulnerability.cvssScore) ? left.vulnerability.cvssScore : -1;
      if (rightCvss !== leftCvss) {
        return rightCvss - leftCvss;
      }
      return left.vulnerability.id.localeCompare(right.vulnerability.id);
    });
  }
};

// src/infrastructure/obsidian/MarkdownSectionMerger.ts
var MANAGED_MARKER_PREFIX = "VULNDASH:SECTION";
var normalizeContent = (value) => value.replace(/\r\n/g, "\n").trim();
var buildStartMarker = (key) => `<!-- ${MANAGED_MARKER_PREFIX} ${key} START -->`;
var buildEndMarker = (key) => `<!-- ${MANAGED_MARKER_PREFIX} ${key} END -->`;
var escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
var MarkdownSectionMerger = class {
  merge(input) {
    const existingContent = normalizeContent(input.existingContent ?? "");
    const analystNotesBody = this.extractAnalystNotesBody(existingContent, input.analystNotesHeading) ?? input.analystNotesPlaceholder;
    const sections = input.managedSections.map((section) => this.renderManagedSection(section));
    return [
      input.title.trim(),
      "",
      ...sections.flatMap(
        (section, index) => index === sections.length - 1 ? [section] : [section, ""]
      ),
      input.analystNotesHeading.trim(),
      "",
      analystNotesBody.trim() || input.analystNotesPlaceholder
    ].join("\n").trimEnd();
  }
  renderManagedSection(section) {
    return [
      buildStartMarker(section.key),
      normalizeContent(section.content),
      buildEndMarker(section.key)
    ].join("\n");
  }
  extractAnalystNotesBody(content, analystNotesHeading) {
    if (!content) {
      return null;
    }
    const escapedHeading = escapeRegExp(analystNotesHeading.trim());
    const analystHeadingPattern = new RegExp(`^${escapedHeading}\\s*$`, "m");
    const match = analystHeadingPattern.exec(content);
    if (!match || match.index === void 0) {
      return null;
    }
    const bodyStart = match.index + match[0].length;
    return content.slice(bodyStart).trim();
  }
  replaceManagedSections(input) {
    let working = normalizeContent(input.existingContent);
    for (const section of input.managedSections) {
      const nextBlock = this.renderManagedSection(section);
      const pattern = new RegExp(
        `${escapeRegExp(buildStartMarker(section.key))}[\\s\\S]*?${escapeRegExp(buildEndMarker(section.key))}`,
        "m"
      );
      working = pattern.test(working) ? working.replace(pattern, nextBlock) : `${working.trimEnd()}

${nextBlock}`;
    }
    return working;
  }
};

// src/infrastructure/obsidian/DailyRollupNoteWriter.ts
var normalizePath2 = (value) => value.trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.?\//, "");
var DailyRollupNoteWriter = class {
  constructor(vault, merger = new MarkdownSectionMerger()) {
    this.vault = vault;
    this.merger = merger;
  }
  async write(input) {
    const folderPath = normalizePath2(input.folderPath);
    const notePath = folderPath.length > 0 ? `${folderPath}/VulnDash Briefing ${input.date}.md` : `VulnDash Briefing ${input.date}.md`;
    await this.ensureFolder(folderPath);
    const exists = await this.vault.exists(notePath);
    const existingContent = exists ? await this.vault.read(notePath) : null;
    const content = this.merger.merge({
      analystNotesHeading: input.document.analystNotesHeading,
      analystNotesPlaceholder: input.document.analystNotesPlaceholder,
      existingContent,
      managedSections: input.document.managedSections,
      title: input.document.title
    });
    if (!exists) {
      await this.vault.create(notePath, content);
      return {
        content,
        created: true,
        path: notePath
      };
    }
    if (existingContent !== content) {
      await this.vault.write(notePath, content);
    }
    return {
      content,
      created: false,
      path: notePath
    };
  }
  async ensureFolder(folderPath) {
    if (!folderPath || folderPath === "/") {
      return;
    }
    if (await this.vault.exists(folderPath)) {
      return;
    }
    const parts = folderPath.split("/").filter(Boolean);
    let current = "";
    for (const part of parts) {
      current = current ? `${current}/${part}` : part;
      if (!await this.vault.exists(current)) {
        await this.vault.createFolder(current);
      }
    }
  }
};

// src/application/sbom/ComponentStorageResolver.ts
var normalizeToken4 = (value) => value.trim().replace(/\s+/g, " ").toLowerCase();
var getTrimmedString4 = (value) => typeof value === "string" ? value.trim() : "";
var getStringList = (value) => {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  if (!Array.isArray(value)) {
    return [];
  }
  return value.map((entry) => getTrimmedString4(entry)).filter((entry) => entry.length > 0);
};
var comparePaths = (left, right) => left.localeCompare(right);
var ComponentNotePathResolver = class {
  constructor(candidates, nameNormalizer = new ProductNameNormalizer()) {
    this.identityService = new ComponentIdentityService();
    this.pathsByBaseName = /* @__PURE__ */ new Map();
    this.pathsByName = /* @__PURE__ */ new Map();
    this.pathsByNameVersion = /* @__PURE__ */ new Map();
    this.pathsBySemanticKey = /* @__PURE__ */ new Map();
    this.nameNormalizer = nameNormalizer;
    for (const candidate of candidates) {
      const reference = this.toReference(candidate);
      this.addValue(this.pathsByBaseName, reference.normalizedBaseName, reference.path);
      for (const normalizedName of reference.normalizedNames) {
        this.addValue(this.pathsByName, normalizedName, reference.path);
      }
      if (reference.nameVersionKey) {
        this.addValue(this.pathsByNameVersion, reference.nameVersionKey, reference.path);
      }
      for (const semanticKey of reference.semanticKeys) {
        this.addValue(this.pathsBySemanticKey, semanticKey, reference.path);
      }
    }
  }
  resolve(component) {
    const purl = getTrimmedString4(component.purl);
    if (purl) {
      const resolved = this.getUniqueMatch(this.pathsBySemanticKey.get(`purl:${this.identityService.normalizePurlValue(purl)}`));
      if (resolved) {
        return resolved;
      }
    }
    const cpe = getTrimmedString4(component.cpe);
    if (cpe) {
      const resolved = this.getUniqueMatch(this.pathsBySemanticKey.get(`cpe:${this.identityService.normalizeCpeValue(cpe)}`));
      if (resolved) {
        return resolved;
      }
    }
    const version = getTrimmedString4(component.version);
    if (version) {
      const nameVersionKey = this.identityService.getNameVersionKeyFromParts(component.name, version);
      if (nameVersionKey) {
        const resolvedFromSemanticKey = this.getUniqueMatch(this.pathsBySemanticKey.get(nameVersionKey));
        if (resolvedFromSemanticKey) {
          return resolvedFromSemanticKey;
        }
        const resolvedFromNameVersion = this.getUniqueMatch(this.pathsByNameVersion.get(nameVersionKey));
        if (resolvedFromNameVersion) {
          return resolvedFromNameVersion;
        }
      }
      const normalizedNameVersion = this.normalizeDisplayName(`${component.name} ${version}`);
      if (normalizedNameVersion) {
        const resolvedFromBaseName = this.getUniqueMatch(this.pathsByBaseName.get(normalizedNameVersion));
        if (resolvedFromBaseName) {
          return resolvedFromBaseName;
        }
      }
    }
    const normalizedName = this.normalizeDisplayName(component.name);
    if (normalizedName) {
      const resolvedFromSemanticName = this.getUniqueMatch(this.pathsByName.get(normalizedName));
      if (resolvedFromSemanticName) {
        return resolvedFromSemanticName;
      }
      const resolvedFromBaseName = this.getUniqueMatch(this.pathsByBaseName.get(normalizedName));
      if (resolvedFromBaseName) {
        return resolvedFromBaseName;
      }
    }
    return null;
  }
  addValue(map, key, path) {
    if (!key) {
      return;
    }
    const current = map.get(key) ?? [];
    if (!current.includes(path)) {
      current.push(path);
      current.sort(comparePaths);
      map.set(key, current);
    }
  }
  getUniqueMatch(paths) {
    if (!paths || paths.length !== 1) {
      return null;
    }
    return paths[0] ?? null;
  }
  normalizeDisplayName(value) {
    const normalized = this.nameNormalizer.normalize(value);
    return normalizeToken4(normalized || value);
  }
  toReference(candidate) {
    const frontmatter = candidate.frontmatter ?? {};
    const path = normalizePath(candidate.path);
    const normalizedBaseName = this.normalizeDisplayName(candidate.basename);
    const names = [
      candidate.basename,
      ...getStringList(frontmatter.name),
      ...getStringList(frontmatter.component),
      ...getStringList(frontmatter.package),
      ...getStringList(frontmatter.title)
    ].map((value) => this.normalizeDisplayName(value)).filter((value, index, values) => value.length > 0 && values.indexOf(value) === index);
    const version = getTrimmedString4(frontmatter.version);
    const nameVersionKey = version && names[0] ? this.identityService.getNameVersionKeyFromParts(names[0], version) : null;
    const semanticKeys = [
      ...getStringList(frontmatter.component_key),
      ...getStringList(frontmatter.componentKey),
      ...getStringList(frontmatter.id),
      ...getStringList(frontmatter.identifiers),
      ...getStringList(frontmatter.aliases)
    ].map((value) => normalizeToken4(value)).filter((value) => value.startsWith("purl:") || value.startsWith("cpe:") || value.startsWith("name-version:"));
    for (const purl of getStringList(frontmatter.purl)) {
      semanticKeys.push(`purl:${this.identityService.normalizePurlValue(purl)}`);
    }
    for (const cpe of getStringList(frontmatter.cpe)) {
      semanticKeys.push(`cpe:${this.identityService.normalizeCpeValue(cpe)}`);
    }
    if (nameVersionKey) {
      semanticKeys.push(nameVersionKey);
    }
    return {
      normalizedBaseName,
      normalizedNames: names,
      nameVersionKey,
      path,
      semanticKeys: Array.from(new Set(semanticKeys))
    };
  }
};

// src/infrastructure/obsidian-adapters/ObsidianNoteResolver.ts
var getFrontmatter = (metadataCache, file) => {
  const frontmatter = metadataCache.getFileCache(file)?.frontmatter;
  if (!frontmatter || typeof frontmatter !== "object") {
    return void 0;
  }
  return frontmatter;
};
var ComponentNoteResolverFactory = class {
  constructor(vault, metadataCache) {
    this.vault = vault;
    this.metadataCache = metadataCache;
  }
  createResolver() {
    const candidates = this.vault.getMarkdownFiles().map((file) => {
      const candidate = {
        basename: file.basename,
        path: normalizePath(file.path)
      };
      const frontmatter = getFrontmatter(this.metadataCache, file);
      if (frontmatter) {
        candidate.frontmatter = frontmatter;
      }
      return candidate;
    });
    return new ComponentNotePathResolver(candidates);
  }
};

// src/infrastructure/storage/CacheHydrator.ts
var CacheHydrator = class {
  constructor(repository, scheduler = new CooperativeScheduler()) {
    this.repository = repository;
    this.scheduler = scheduler;
  }
  async hydrateLatest(options) {
    const hydrated = await this.repository.loadLatest(options.limit, options.pageSize);
    if (hydrated.length > options.pageSize) {
      await this.scheduler.yieldToHost({ timeoutMs: 16 });
    }
    return hydrated;
  }
};

// src/infrastructure/storage/CachePruner.ts
var CachePruner = class {
  constructor(repository, scheduler = new CooperativeScheduler(), getActivePurls) {
    this.repository = repository;
    this.scheduler = scheduler;
    this.getActivePurls = getActivePurls;
    this.scheduled = false;
  }
  schedule(policy) {
    if (this.scheduled) {
      return;
    }
    this.scheduled = true;
    const run = async () => {
      try {
        await this.scheduler.yieldToHost({ timeoutMs: 50 });
        const result = await this.pruneNow(policy);
        console.info("[vulndash.cache.prune.complete]", result);
      } catch (error) {
        console.warn("[vulndash.cache.prune_failed]", error);
      } finally {
        this.scheduled = false;
      }
    };
    void run();
  }
  async pruneNow(policy) {
    const nowMs = Date.now();
    const activePurls = this.toOrderedUniqueStrings(await this.getActivePurls?.() ?? []);
    const activePurlSet = new Set(activePurls);
    if (activePurls.length > 0) {
      await this.repository.markComponentQueriesSeen(activePurls, nowMs);
    }
    const componentQueryOrphanedCount = activePurls.length > 0 ? await this.repository.pruneOrphanedComponentQueries(activePurlSet) : 0;
    const componentQueryExpiredCount = await this.repository.pruneExpiredComponentQueries(nowMs - policy.ttlMs);
    const expiredCount = await this.repository.pruneExpired(nowMs - policy.ttlMs, policy.pruneBatchSize);
    const overCapCount = await this.repository.pruneToHardCap(policy.hardCap, policy.pruneBatchSize);
    return {
      componentQueryExpiredCount,
      componentQueryOrphanedCount,
      expiredCount,
      overCapCount
    };
  }
  toOrderedUniqueStrings(values) {
    const normalizedValues = [];
    const seen = /* @__PURE__ */ new Set();
    for (const value of values) {
      const normalized = value.trim();
      if (!normalized || seen.has(normalized)) {
        continue;
      }
      seen.add(normalized);
      normalizedValues.push(normalized);
    }
    return normalizedValues;
  }
};

// src/domain/triage/TriageRecord.ts
var normalizeRequiredString = (value, fieldName) => {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`TriageRecord requires a non-empty ${fieldName}.`);
  }
  return normalized;
};
var normalizeOptionalString = (value) => {
  const normalized = value?.trim();
  return normalized && normalized.length > 0 ? normalized : void 0;
};
var normalizeUpdatedAt = (value) => {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error("TriageRecord requires a valid updatedAt timestamp.");
  }
  return new Date(timestamp).toISOString();
};
var TriageRecord = class _TriageRecord {
  constructor(props) {
    this.correlationKey = props.correlationKey;
    this.vulnerabilityId = props.vulnerabilityId;
    this.source = props.source;
    this.state = props.state;
    this.updatedAt = props.updatedAt;
    this.reason = props.reason;
    this.ticketRef = props.ticketRef;
    this.updatedBy = props.updatedBy;
    Object.freeze(this);
  }
  static create(props) {
    return new _TriageRecord({
      correlationKey: normalizeRequiredString(props.correlationKey, "correlationKey"),
      reason: normalizeOptionalString(props.reason),
      source: normalizeRequiredString(props.source, "source"),
      state: parseTriageState(props.state),
      ticketRef: normalizeOptionalString(props.ticketRef),
      updatedAt: normalizeUpdatedAt(props.updatedAt),
      updatedBy: normalizeOptionalString(props.updatedBy),
      vulnerabilityId: normalizeRequiredString(props.vulnerabilityId, "vulnerabilityId")
    });
  }
  toJSON() {
    return {
      correlationKey: this.correlationKey,
      vulnerabilityId: this.vulnerabilityId,
      source: this.source,
      state: this.state,
      updatedAt: this.updatedAt,
      ...this.reason ? { reason: this.reason } : {},
      ...this.ticketRef ? { ticketRef: this.ticketRef } : {},
      ...this.updatedBy ? { updatedBy: this.updatedBy } : {}
    };
  }
};

// src/infrastructure/storage/VulnCacheDb.ts
var getIndexedDbFactory = () => typeof indexedDB === "undefined" ? null : indexedDB;
var awaitRequest = (request) => new Promise((resolve, reject) => {
  request.addEventListener("success", () => resolve(request.result));
  request.addEventListener("error", () => reject(request.error ?? new Error("IndexedDB request failed.")));
});
var awaitTransaction = (transaction) => new Promise((resolve, reject) => {
  transaction.addEventListener("complete", () => resolve());
  transaction.addEventListener("abort", () => reject(transaction.error ?? new Error("IndexedDB transaction aborted.")));
  transaction.addEventListener("error", () => reject(transaction.error ?? new Error("IndexedDB transaction failed.")));
});
var VulnCacheDb = class {
  constructor() {
    this.databasePromise = null;
  }
  async close() {
    if (!this.databasePromise) {
      return;
    }
    const database = await this.databasePromise;
    database.close();
    this.databasePromise = null;
  }
  async open() {
    if (!this.databasePromise) {
      this.databasePromise = this.openDatabase();
    }
    return this.databasePromise;
  }
  async openDatabase() {
    const indexedDbFactory = getIndexedDbFactory();
    if (!indexedDbFactory) {
      throw new Error("IndexedDB is not available in this runtime.");
    }
    const request = indexedDbFactory.open(VULN_CACHE_DB_NAME, VULN_CACHE_DB_VERSION);
    request.addEventListener("upgradeneeded", (event) => {
      if (!request.result) {
        return;
      }
      applyVulnCacheSchemaUpgrade(request.result, event.oldVersion, event.newVersion);
    });
    return awaitRequest(request);
  }
};

// src/infrastructure/storage/IndexedDbTriageRepository.ts
var toDomainRecord = (record) => TriageRecord.create({
  correlationKey: record.correlationKey,
  source: record.source,
  state: record.state,
  updatedAt: record.updatedAt,
  vulnerabilityId: record.vulnerabilityId,
  ...record.reason ? { reason: record.reason } : {},
  ...record.ticketRef ? { ticketRef: record.ticketRef } : {},
  ...record.updatedBy ? { updatedBy: record.updatedBy } : {}
});
var IndexedDbTriageRepository = class {
  constructor(database) {
    this.database = database;
  }
  async getByCorrelationKey(correlationKey) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.triageRecords, "readonly");
    const persistedRecord = await awaitRequest(
      transaction.objectStore(VULN_CACHE_STORES.triageRecords).get(correlationKey)
    );
    await awaitTransaction(transaction);
    return persistedRecord ? toDomainRecord(persistedRecord) : null;
  }
  async getByCorrelationKeys(correlationKeys) {
    if (correlationKeys.length === 0) {
      return /* @__PURE__ */ new Map();
    }
    const uniqueKeys = Array.from(new Set(correlationKeys));
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.triageRecords, "readonly");
    const store = transaction.objectStore(VULN_CACHE_STORES.triageRecords);
    const requests = uniqueKeys.map((correlationKey) => ({
      correlationKey,
      request: store.get(correlationKey)
    }));
    const resolvedRecords = await Promise.all(requests.map(async ({ correlationKey, request }) => {
      const persistedRecord = await awaitRequest(request);
      return [correlationKey, persistedRecord];
    }));
    await awaitTransaction(transaction);
    const records = /* @__PURE__ */ new Map();
    for (const [correlationKey, persistedRecord] of resolvedRecords) {
      if (!persistedRecord) {
        continue;
      }
      records.set(correlationKey, toDomainRecord(persistedRecord));
    }
    return records;
  }
  async save(record) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.triageRecords, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.triageRecords);
    const existingRecord = await awaitRequest(store.get(record.correlationKey));
    const nextPersistedRecord = createPersistedTriageRecord(record);
    if (existingRecord && existingRecord.updatedAtMs >= nextPersistedRecord.updatedAtMs) {
      await awaitTransaction(transaction);
      return toDomainRecord(existingRecord);
    }
    store.put(nextPersistedRecord);
    await awaitTransaction(transaction);
    return record;
  }
};

// src/domain/triage/TriageCorrelation.ts
var normalizeSegment = (value) => value.trim().toLowerCase();
var normalizeRequiredSegment = (value, fieldName) => {
  const normalized = normalizeSegment(value);
  if (normalized.length === 0) {
    throw new Error(`Triage correlation requires a non-empty ${fieldName}.`);
  }
  return normalized;
};
var resolveTriageIdentity = (input) => {
  const directId = normalizeSegment(input.vulnerabilityId);
  if (directId.length > 0) {
    return directId;
  }
  const fallbacks = [
    input.metadata?.cveId,
    input.metadata?.ghsaId,
    ...input.metadata?.identifiers ?? [],
    ...input.metadata?.aliases ?? []
  ].map((value) => typeof value === "string" ? normalizeSegment(value) : "").filter((value) => value.length > 0);
  const fallbackIdentity = fallbacks[0];
  if (!fallbackIdentity) {
    throw new Error("Triage correlation requires a vulnerability identity.");
  }
  return fallbackIdentity;
};
var buildTriageCorrelationKey = (input) => `${normalizeRequiredSegment(input.source, "source")}::${resolveTriageIdentity(input)}`;
var buildTriageCorrelationKeyForVulnerability = (vulnerability) => buildTriageCorrelationKey({
  source: vulnerability.source,
  vulnerabilityId: vulnerability.id,
  ...vulnerability.metadata ? { metadata: vulnerability.metadata } : {}
});

// src/application/triage/JoinTriageState.ts
var JoinTriageState = class {
  constructor(repository) {
    this.repository = repository;
  }
  async execute(vulnerabilities) {
    const correlationKeys = Array.from(new Set(vulnerabilities.map(
      (vulnerability) => buildTriageCorrelationKeyForVulnerability(vulnerability)
    )));
    const triageByCorrelationKey = await this.repository.getByCorrelationKeys(correlationKeys);
    return vulnerabilities.map((vulnerability) => {
      const correlationKey = buildTriageCorrelationKeyForVulnerability(vulnerability);
      const triageRecord = triageByCorrelationKey.get(correlationKey) ?? null;
      return {
        cacheKey: buildVulnerabilityCacheKey(vulnerability),
        correlationKey,
        triageRecord,
        triageState: triageRecord?.state ?? DEFAULT_TRIAGE_STATE,
        vulnerability
      };
    });
  }
};

// src/infrastructure/storage/LegacyDataMigration.ts
var isRecord3 = (value) => typeof value === "object" && value !== null;
var isStringArray = (value) => Array.isArray(value) && value.every((entry) => typeof entry === "string");
var isVulnerability = (value) => {
  if (!isRecord3(value)) {
    return false;
  }
  return typeof value.id === "string" && typeof value.source === "string" && typeof value.title === "string" && typeof value.summary === "string" && typeof value.publishedAt === "string" && typeof value.updatedAt === "string" && typeof value.cvssScore === "number" && typeof value.severity === "string" && isStringArray(value.references) && isStringArray(value.affectedProducts);
};
var collectLegacyVulnerabilities = (data) => {
  if (!data) {
    return [];
  }
  const candidates = [data.cachedVulnerabilities, data.vulnerabilities, data.cache];
  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }
    const vulnerabilities = candidate.filter(isVulnerability);
    if (vulnerabilities.length > 0) {
      return vulnerabilities;
    }
  }
  return [];
};
var resolveLegacySourceId = (source, feeds) => {
  const trimmed = source.trim();
  const feedByExactName = feeds.find((feed) => feed.name === trimmed);
  if (feedByExactName) {
    return feedByExactName.id;
  }
  const normalized = trimmed.toLowerCase();
  const feedByNormalizedName = feeds.find((feed) => feed.name.trim().toLowerCase() === normalized);
  if (feedByNormalizedName) {
    return feedByNormalizedName.id;
  }
  if (BUILT_IN_FEEDS.GITHUB_ADVISORY.legacySourceAliases?.some((alias) => alias === normalized)) {
    return BUILT_IN_FEEDS.GITHUB_ADVISORY.id;
  }
  if (BUILT_IN_FEEDS.NVD.legacySourceAliases?.some((alias) => alias === normalized)) {
    return BUILT_IN_FEEDS.NVD.id;
  }
  return normalized.replace(/[^a-z0-9._-]+/g, "-");
};
var LegacyDataMigration = class {
  constructor(cacheRepository, syncMetadataRepository) {
    this.cacheRepository = cacheRepository;
    this.syncMetadataRepository = syncMetadataRepository;
  }
  async migrate(data, feeds) {
    if (!data) {
      return {
        migratedCursorCount: 0,
        migratedVulnerabilityCount: 0,
        removedLegacyFields: false
      };
    }
    const legacyVulnerabilities = collectLegacyVulnerabilities(data);
    const groupedBySource = /* @__PURE__ */ new Map();
    for (const vulnerability of legacyVulnerabilities) {
      const sourceId = resolveLegacySourceId(vulnerability.source, feeds);
      const current = groupedBySource.get(sourceId) ?? [];
      current.push(vulnerability);
      groupedBySource.set(sourceId, current);
    }
    for (const [sourceId, vulnerabilities] of groupedBySource.entries()) {
      const lastSeenAt = data.sourceSyncCursor?.[sourceId] ?? data.sourceSyncCursor?.[vulnerabilities[0]?.source ?? ""] ?? (/* @__PURE__ */ new Date()).toISOString();
      await this.cacheRepository.importLegacySnapshot(sourceId, vulnerabilities, lastSeenAt);
    }
    let migratedCursorCount = 0;
    for (const [sourceId, successfulAt] of Object.entries(data.sourceSyncCursor ?? {})) {
      if (!successfulAt.trim()) {
        continue;
      }
      const resolvedSourceId = resolveLegacySourceId(sourceId, feeds);
      await this.syncMetadataRepository.recordSuccess(resolvedSourceId, successfulAt, successfulAt);
      migratedCursorCount += 1;
    }
    const removedLegacyFields = Array.isArray(data.cache) || Array.isArray(data.cachedVulnerabilities) || Array.isArray(data.vulnerabilities) || Object.keys(data.sourceSyncCursor ?? {}).length > 0;
    return {
      migratedCursorCount,
      migratedVulnerabilityCount: legacyVulnerabilities.length,
      removedLegacyFields
    };
  }
};

// src/application/triage/SetTriageState.ts
var SetTriageState = class {
  constructor(repository) {
    this.repository = repository;
    this.lastIssuedUpdatedAtMs = 0;
  }
  async execute(input) {
    const updatedAt = input.updatedAt ?? this.issueUpdatedAt();
    const record = TriageRecord.create({
      correlationKey: buildTriageCorrelationKeyForVulnerability(input.vulnerability),
      source: input.vulnerability.source,
      state: input.state,
      updatedAt,
      vulnerabilityId: input.vulnerability.id,
      ...input.reason ? { reason: input.reason } : {},
      ...input.ticketRef ? { ticketRef: input.ticketRef } : {},
      ...input.updatedBy ? { updatedBy: input.updatedBy } : {}
    });
    return this.repository.save(record);
  }
  issueUpdatedAt() {
    const now = Date.now();
    const nextMs = now > this.lastIssuedUpdatedAtMs ? now : this.lastIssuedUpdatedAtMs + 1;
    this.lastIssuedUpdatedAtMs = nextMs;
    return new Date(nextMs).toISOString();
  }
};

// src/infrastructure/storage/SyncMetadataRepository.ts
var SyncMetadataRepository = class {
  constructor(database) {
    this.database = database;
  }
  async getAllLastSuccessfulSyncAt() {
    const records = await this.listRecords();
    return Object.fromEntries(records.flatMap((record) => record.lastSuccessfulSyncAt ? [[record.sourceId, record.lastSuccessfulSyncAt]] : []));
  }
  async getRecord(sourceId) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.syncMetadata, "readonly");
    const store = transaction.objectStore(VULN_CACHE_STORES.syncMetadata);
    const record = await awaitRequest(store.get(sourceId));
    await awaitTransaction(transaction);
    return record ?? null;
  }
  async getLastSuccessfulSyncAt(sourceId) {
    return (await this.getRecord(sourceId))?.lastSuccessfulSyncAt ?? null;
  }
  async listRecords() {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.syncMetadata, "readonly");
    const store = transaction.objectStore(VULN_CACHE_STORES.syncMetadata);
    const records = await awaitRequest(store.getAll());
    await awaitTransaction(transaction);
    return records.sort((left, right) => left.sourceId.localeCompare(right.sourceId));
  }
  async recordAttempt(sourceId, attemptedAt) {
    const existing = await this.getRecord(sourceId);
    await this.putRecord({
      cacheSchemaVersion: VULN_CACHE_DB_VERSION,
      lastAttemptedSyncAt: attemptedAt,
      ...existing?.lastSuccessfulSyncAt ? { lastSuccessfulSyncAt: existing.lastSuccessfulSyncAt } : {},
      sourceId,
      updatedAtMs: Date.now()
    });
  }
  async recordSuccess(sourceId, attemptedAt, successfulAt) {
    await this.putRecord({
      cacheSchemaVersion: VULN_CACHE_DB_VERSION,
      lastAttemptedSyncAt: attemptedAt,
      lastSuccessfulSyncAt: successfulAt,
      sourceId,
      updatedAtMs: Date.now()
    });
  }
  async putRecord(record) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.syncMetadata, "readwrite");
    transaction.objectStore(VULN_CACHE_STORES.syncMetadata).put(record);
    await awaitTransaction(transaction);
  }
};

// src/infrastructure/storage/VulnCacheRepository.ts
var VulnCacheRepository = class {
  constructor(database) {
    this.database = database;
  }
  async count() {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readonly");
    const count = await this.awaitRequest(transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).count());
    await awaitTransaction(transaction);
    return count;
  }
  async loadLatest(limit, pageSize) {
    if (limit <= 0) {
      return [];
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readonly");
    const index = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).index(VULN_CACHE_INDEXES.byRetentionRank);
    const records = await this.collectCursorValues(index.openCursor(null, "prev"), limit, pageSize);
    await awaitTransaction(transaction);
    return records.map((record) => record.vulnerability);
  }
  async loadSourceSnapshot(sourceId) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readonly");
    const index = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).index(VULN_CACHE_INDEXES.bySourceId);
    const records = await this.collectCursorValues(index.openCursor(IDBKeyRange.only(sourceId)), Number.POSITIVE_INFINITY, 250);
    await awaitTransaction(transaction);
    const cacheByKey = /* @__PURE__ */ new Map();
    const originByKey = /* @__PURE__ */ new Map();
    for (const record of records) {
      const runtimeCacheKey = buildVulnerabilityCacheKey(record.vulnerability);
      cacheByKey.set(runtimeCacheKey, record.vulnerability);
      originByKey.set(runtimeCacheKey, sourceId);
    }
    return {
      cacheByKey,
      originByKey
    };
  }
  async pruneExpired(cutoffMs, batchSize) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.byLastSeenAt);
    let deleted = 0;
    await this.iterateCursor(index.openCursor(IDBKeyRange.upperBound(cutoffMs)), async (cursor) => {
      store.delete(cursor.primaryKey);
      deleted += 1;
      return deleted % Math.max(batchSize, 1) === 0;
    });
    await awaitTransaction(transaction);
    return deleted;
  }
  async pruneToHardCap(hardCap, batchSize) {
    const count = await this.count();
    if (count <= hardCap) {
      return 0;
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.byRetentionRank);
    let seen = 0;
    let deleted = 0;
    await this.iterateCursor(index.openCursor(null, "prev"), async (cursor) => {
      seen += 1;
      if (seen <= hardCap) {
        return seen % Math.max(batchSize, 1) === 0;
      }
      store.delete(cursor.primaryKey);
      deleted += 1;
      return deleted % Math.max(batchSize, 1) === 0;
    });
    await awaitTransaction(transaction);
    return deleted;
  }
  async replaceSourceSnapshot(sourceId, vulnerabilities, syncedAt) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.bySourceId);
    const existingRecords = await this.collectCursorValues(index.openCursor(IDBKeyRange.only(sourceId)), Number.POSITIVE_INFINITY, 250);
    const existingKeys = new Set(existingRecords.map((record) => record.cacheKey));
    const retainedKeys = /* @__PURE__ */ new Set();
    const createdAtMs = Date.now();
    for (const vulnerability of vulnerabilities) {
      const record = createPersistedVulnerabilityRecord(sourceId, vulnerability, syncedAt, createdAtMs);
      retainedKeys.add(record.cacheKey);
      store.put(record);
    }
    for (const key of existingKeys) {
      if (!retainedKeys.has(key)) {
        store.delete(key);
      }
    }
    await awaitTransaction(transaction);
  }
  async importLegacySnapshot(sourceId, vulnerabilities, lastSeenAt) {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const createdAtMs = Date.now();
    for (const vulnerability of vulnerabilities) {
      store.put(createPersistedVulnerabilityRecord(sourceId, vulnerability, lastSeenAt, createdAtMs));
    }
    await awaitTransaction(transaction);
  }
  async listPersistedRecords() {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readonly");
    const records = await this.collectCursorValues(
      transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).openCursor(),
      Number.POSITIVE_INFINITY,
      250
    );
    await awaitTransaction(transaction);
    return records.sort(comparePersistedRecordsForHardCap);
  }
  async loadComponentQueries(purls) {
    const uniquePurls = this.toOrderedUniqueStrings(purls);
    if (uniquePurls.length === 0) {
      return /* @__PURE__ */ new Map();
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, "readonly");
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    const records = await Promise.all(uniquePurls.map(async (purl) => {
      const record = await this.awaitRequest(store.get(purl));
      return [purl, record];
    }));
    await awaitTransaction(transaction);
    const result = /* @__PURE__ */ new Map();
    for (const [purl, record] of records) {
      if (record) {
        result.set(purl, record);
      }
    }
    return result;
  }
  async saveComponentQueries(records) {
    const recordsByPurl = /* @__PURE__ */ new Map();
    for (const record of records) {
      const existing = recordsByPurl.get(record.purl);
      recordsByPurl.set(record.purl, this.mergeComponentQueryRecord(existing, record));
    }
    if (recordsByPurl.size === 0) {
      return;
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    const existingRecords = await Promise.all(Array.from(recordsByPurl.keys()).map(async (purl) => {
      const existing = await this.awaitRequest(store.get(purl));
      return [purl, existing];
    }));
    for (const [purl, existing] of existingRecords) {
      const nextRecord = recordsByPurl.get(purl);
      if (nextRecord) {
        store.put(this.mergeComponentQueryRecord(existing, nextRecord));
      }
    }
    await awaitTransaction(transaction);
  }
  async markComponentQueriesSeen(purls, seenAtMs) {
    const uniquePurls = this.toOrderedUniqueStrings(purls);
    if (uniquePurls.length === 0) {
      return;
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    const existingRecords = await Promise.all(uniquePurls.map(async (purl) => {
      const record = await this.awaitRequest(store.get(purl));
      return [purl, record];
    }));
    for (const [, record] of existingRecords) {
      if (!record) {
        continue;
      }
      const nextLastSeenAtMs = Math.max(record.lastSeenInWorkspaceAtMs, seenAtMs);
      if (nextLastSeenAtMs !== record.lastSeenInWorkspaceAtMs) {
        store.put({
          ...record,
          lastSeenInWorkspaceAtMs: nextLastSeenAtMs
        });
      }
    }
    await awaitTransaction(transaction);
  }
  async pruneOrphanedComponentQueries(activePurls) {
    const records = await this.listComponentQueryRecords();
    const purlsToDelete = records.filter((record) => !activePurls.has(record.purl)).map((record) => record.purl);
    if (purlsToDelete.length === 0) {
      return 0;
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    for (const purl of purlsToDelete) {
      store.delete(purl);
    }
    await awaitTransaction(transaction);
    return purlsToDelete.length;
  }
  async pruneExpiredComponentQueries(cutoffMs) {
    const records = await this.listComponentQueryRecords();
    const purlsToDelete = records.filter((record) => Math.max(record.lastQueriedAtMs, record.lastSeenInWorkspaceAtMs) < cutoffMs).map((record) => record.purl);
    if (purlsToDelete.length === 0) {
      return 0;
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, "readwrite");
    const store = transaction.objectStore(VULN_CACHE_STORES.componentQueries);
    for (const purl of purlsToDelete) {
      store.delete(purl);
    }
    await awaitTransaction(transaction);
    return purlsToDelete.length;
  }
  async loadVulnerabilitiesByCacheKeys(keys) {
    const uniqueKeys = this.toOrderedUniqueStrings(keys);
    if (uniqueKeys.length === 0) {
      return [];
    }
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, "readonly");
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const records = await Promise.all(uniqueKeys.map(async (key) => {
      const record = await this.awaitRequest(store.get(key));
      return [key, record];
    }));
    await awaitTransaction(transaction);
    const vulnerabilities = [];
    for (const [, record] of records) {
      if (record) {
        vulnerabilities.push(record.vulnerability);
      }
    }
    return vulnerabilities;
  }
  async awaitRequest(request) {
    return new Promise((resolve, reject) => {
      request.addEventListener("success", () => resolve(request.result));
      request.addEventListener("error", () => reject(request.error ?? new Error("IndexedDB request failed.")));
    });
  }
  async collectCursorValues(request, limit, pageSize) {
    const values = [];
    await this.iterateCursor(request, async (cursor) => {
      values.push(cursor.value);
      return values.length % Math.max(pageSize, 1) === 0;
    }, limit);
    return values;
  }
  async listComponentQueryRecords() {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.componentQueries, "readonly");
    const records = await this.awaitRequest(
      transaction.objectStore(VULN_CACHE_STORES.componentQueries).getAll()
    );
    await awaitTransaction(transaction);
    return records;
  }
  mergeComponentQueryRecord(existing, incoming) {
    if (!existing) {
      return incoming;
    }
    const nextLastSeenInWorkspaceAtMs = Math.max(existing.lastSeenInWorkspaceAtMs, incoming.lastSeenInWorkspaceAtMs);
    if (incoming.lastQueriedAtMs > existing.lastQueriedAtMs) {
      return {
        ...incoming,
        lastSeenInWorkspaceAtMs: nextLastSeenInWorkspaceAtMs
      };
    }
    if (incoming.lastQueriedAtMs === existing.lastQueriedAtMs) {
      return {
        ...incoming,
        lastSeenInWorkspaceAtMs: nextLastSeenInWorkspaceAtMs
      };
    }
    if (nextLastSeenInWorkspaceAtMs === existing.lastSeenInWorkspaceAtMs) {
      return existing;
    }
    return {
      ...existing,
      lastSeenInWorkspaceAtMs: nextLastSeenInWorkspaceAtMs
    };
  }
  toOrderedUniqueStrings(values) {
    const uniqueValues = [];
    const seen = /* @__PURE__ */ new Set();
    for (const value of values) {
      if (seen.has(value)) {
        continue;
      }
      seen.add(value);
      uniqueValues.push(value);
    }
    return uniqueValues;
  }
  async iterateCursor(request, onCursor, limit = Number.POSITIVE_INFINITY) {
    let seen = 0;
    await new Promise((resolve, reject) => {
      request.addEventListener("error", () => reject(request.error ?? new Error("IndexedDB cursor failed.")));
      request.addEventListener("success", () => {
        const cursor = request.result;
        if (!cursor || seen >= limit) {
          resolve();
          return;
        }
        void (async () => {
          try {
            seen += 1;
            const shouldYield = await onCursor(cursor);
            if (seen >= limit) {
              resolve();
              return;
            }
            if (shouldYield) {
              setTimeout(() => cursor.continue(), 0);
              return;
            }
            cursor.continue();
          } catch (error) {
            reject(error);
          }
        })();
      });
    });
  }
};

// src/application/VulnDashAppModule.ts
var VulnDashAppModule = class _VulnDashAppModule {
  constructor(options, services) {
    this.alertEngine = new AlertEngine();
    this.componentInventoryService = new ComponentInventoryService();
    this.componentPreferenceService = new ComponentPreferenceService();
    this.componentVulnerabilityLinkService = new ComponentVulnerabilityLinkService();
    this.relationshipNormalizer = new RelationshipNormalizer();
    this.sbomCatalogService = new SbomCatalogService();
    this.sbomComparisonService = new SbomComparisonService();
    this.sbomComponentIndex = new SbomComponentIndex();
    this.sbomFilterMergeService = new SbomFilterMergeService();
    this.settingsMigrator = new SettingsMigrator();
    this.dailyRollupGenerator = services.dailyRollupGenerator;
    this.projectNoteLookup = services.projectNoteLookup;
    this.sbomImportService = services.sbomImportService;
    this.sbomProjectMappingRepository = services.sbomProjectMappingRepository;
    this.resolveAffectedProjects = new ResolveAffectedProjects(
      this.sbomProjectMappingRepository,
      {
        getByPaths: async (references) => this.projectNoteLookup.getByPaths(references)
      }
    );
    this.createHttpClient = options.createHttpClient ?? (() => new HttpClient());
    this.getActiveWorkspacePurls = options.getActiveWorkspacePurls;
    this.storageScheduler = options.storageScheduler ?? new CooperativeScheduler();
  }
  static create(options) {
    const normalizePath3 = options.normalizePath ?? ((path) => path);
    const projectNoteLookup = new ProjectNoteLookupService(options.vault);
    const notePathResolverFactory = new ComponentNoteResolverFactory(
      options.vault,
      options.metadataCache
    );
    const sbomImportService = new SbomImportService(
      options.vault.adapter,
      void 0,
      notePathResolverFactory
    );
    const dailyRollupGenerator = new DailyRollupGenerator(
      new SelectRollupFindings(),
      new RollupMarkdownRenderer(),
      new DailyRollupNoteWriter({
        create: async (path, noteContent) => {
          await options.vault.create(normalizePath3(path), noteContent);
        },
        createFolder: async (path) => {
          await options.vault.createFolder(normalizePath3(path));
        },
        exists: async (path) => options.vault.adapter.exists(normalizePath3(path)),
        read: async (path) => options.vault.adapter.read(normalizePath3(path)),
        write: async (path, noteContent) => {
          await options.vault.adapter.write(normalizePath3(path), noteContent);
        }
      })
    );
    const sbomProjectMappingRepository = new SbomProjectMappingRepository(
      options.getSboms,
      options.updateSbomConfig
    );
    return new _VulnDashAppModule(options, {
      dailyRollupGenerator,
      projectNoteLookup,
      sbomImportService,
      sbomProjectMappingRepository
    });
  }
  createSyncService(options) {
    const client = this.createHttpClient();
    const osvQueryCache = options.persistentCacheServices?.cacheRepository;
    const feeds = buildFeedsFromConfig(options.settings.feeds, client, options.settings.syncControls, {
      ...osvQueryCache ? { osvQueryCache } : {},
      getPurls: this.getActiveWorkspacePurls
    });
    return new VulnerabilitySyncService({
      controls: options.settings.syncControls,
      feeds,
      ...options.persistentCacheServices ? {
        persistence: {
          cacheHydrationLimit: options.settings.cacheStorage.hydrateMaxItems,
          cacheHydrationPageSize: options.settings.cacheStorage.hydratePageSize,
          cacheStore: options.persistentCacheServices.cacheRepository,
          metadataStore: options.persistentCacheServices.metadataRepository
        }
      } : {},
      onPipelineEvent: options.onPipelineEvent,
      state: {
        cache: [...options.cachedVulnerabilities],
        sourceSyncCursor: options.settings.sourceSyncCursor
      }
    });
  }
  async initializePersistentCache(loadedPluginData, settings) {
    try {
      const cacheDb = new VulnCacheDb();
      await cacheDb.open();
      const cacheRepository = new VulnCacheRepository(cacheDb);
      const metadataRepository = new SyncMetadataRepository(cacheDb);
      const triageRepository = new IndexedDbTriageRepository(cacheDb);
      const cacheHydrator = new CacheHydrator(cacheRepository, this.storageScheduler);
      const cachePruner = new CachePruner(
        cacheRepository,
        this.storageScheduler,
        this.getActiveWorkspacePurls
      );
      const persistentCacheServices = {
        cacheDb,
        cacheHydrator,
        cachePruner,
        cacheRepository,
        metadataRepository,
        triageRepository
      };
      const triageJoinUseCase = new JoinTriageState(triageRepository);
      const triageSetUseCase = new SetTriageState(triageRepository);
      const migration = await new LegacyDataMigration(cacheRepository, metadataRepository).migrate(
        loadedPluginData,
        settings.feeds
      );
      const hydrated = await cacheHydrator.hydrateLatest({
        limit: settings.cacheStorage.hydrateMaxItems,
        pageSize: settings.cacheStorage.hydratePageSize
      });
      cachePruner.schedule(settings.cacheStorage);
      return {
        cachedVulnerabilities: hydrated,
        lastFetchAt: hydrated.length > 0 ? Date.now() : 0,
        persistentCacheServices,
        removedLegacyFields: migration.removedLegacyFields,
        triageJoinUseCase,
        triageSetUseCase
      };
    } catch (error) {
      console.warn("[vulndash.cache.persistence_unavailable]", error);
      return {
        cachedVulnerabilities: [],
        lastFetchAt: 0,
        persistentCacheServices: null,
        removedLegacyFields: false,
        triageJoinUseCase: null,
        triageSetUseCase: null
      };
    }
  }
  invalidateMarkdownNotePathCaches() {
    this.sbomImportService.invalidateAllCaches();
  }
  invalidateSbomCache(sbomId) {
    this.sbomImportService.invalidateCache(sbomId);
  }
  listProjectNotes() {
    return this.projectNoteLookup.listProjectNotes();
  }
  async resolveProjectNotePath(notePath, displayName) {
    return this.projectNoteLookup.resolveByPath(notePath, displayName);
  }
  async closePersistentCache(persistentCacheServices) {
    if (!persistentCacheServices) {
      return;
    }
    await persistentCacheServices.cacheDb.close();
  }
};

// tests/application/VulnDashAppModule.test.ts
var createMarkdownFile = (path) => Object.assign(new TFile(), {
  basename: path.split("/").at(-1)?.replace(/\.md$/i, "") ?? path,
  path: normalizePath(path)
});
test("VulnDashAppModule exposes explicit note lookup and cache invalidation entrypoints", async () => {
  const projectFile = createMarkdownFile("projects/portal-web.md");
  const vault = {
    adapter: {
      exists: async () => true,
      read: async () => "",
      write: async () => void 0
    },
    create: async () => ({}),
    createFolder: async () => ({}),
    getAbstractFileByPath: (path) => normalizePath(path) === projectFile.path ? projectFile : null,
    getMarkdownFiles: () => [projectFile]
  };
  const module = VulnDashAppModule.create({
    getActiveWorkspacePurls: async () => [],
    getSboms: () => [],
    metadataCache: {
      getFileCache: () => null
    },
    normalizePath,
    updateSbomConfig: async () => void 0,
    vault
  });
  assert.deepEqual(module.listProjectNotes(), [{
    displayName: "portal-web",
    notePath: "projects/portal-web.md"
  }]);
  const linked = await module.resolveProjectNotePath("projects/portal-web.md");
  assert.equal(linked.status, "linked");
  assert.equal(linked.displayName, "portal-web");
  let invalidateAllCachesCalls = 0;
  let invalidatedSbomId = null;
  const importService = module.sbomImportService;
  importService.invalidateAllCaches = () => {
    invalidateAllCachesCalls += 1;
  };
  importService.invalidateCache = (sbomId) => {
    invalidatedSbomId = sbomId;
  };
  module.invalidateMarkdownNotePathCaches();
  module.invalidateSbomCache("sbom-1");
  assert.equal(invalidateAllCachesCalls, 1);
  assert.equal(invalidatedSbomId, "sbom-1");
});
