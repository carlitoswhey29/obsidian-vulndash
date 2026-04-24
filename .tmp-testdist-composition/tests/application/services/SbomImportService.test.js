// tests/application/services/SbomImportService.test.ts
import assert from "node:assert/strict";
import test from "node:test";

// tests/support/obsidian-stub.ts
var normalizePath = (path) => path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.\//, "");

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

// src/domain/value-objects/Severity.ts
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

// src/infrastructure/parsers/CycloneDxParser.ts
var isRecord = (value) => typeof value === "object" && value !== null;
var getTrimmedString = (value) => {
  if (typeof value !== "string") {
    return void 0;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : void 0;
};
var getFiniteNumber = (value) => typeof value === "number" && Number.isFinite(value) ? value : void 0;
var normalizeSeverity = (severity) => {
  const normalized = getTrimmedString(severity)?.toLowerCase();
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
var compareVulnerabilities = (left, right) => {
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
var buildCweGroups = (vulnerabilities) => {
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
    const expression = getTrimmedString(licenseChoice.expression);
    if (expression) {
      return expression;
    }
    if (!isRecord(licenseChoice.license)) {
      continue;
    }
    const license = licenseChoice.license;
    const id = getTrimmedString(license.id);
    if (id) {
      return id;
    }
    const name = getTrimmedString(license.name);
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
    id: getTrimmedString(vulnerability.id) ?? getTrimmedString(vulnerability["bom-ref"]) ?? "unknown-vulnerability"
  };
  const bomRef = getTrimmedString(vulnerability["bom-ref"]);
  if (bomRef) {
    normalized.bomRef = bomRef;
  }
  const sourceName = getTrimmedString(vulnerabilitySource?.name) ?? getTrimmedString(ratingSource?.name);
  if (sourceName) {
    normalized.sourceName = sourceName;
  }
  const sourceUrl = getTrimmedString(vulnerabilitySource?.url) ?? getTrimmedString(ratingSource?.url);
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
  const method = getTrimmedString(firstRating?.method);
  if (method) {
    normalized.method = method;
  }
  const vector = getTrimmedString(firstRating?.vector);
  if (vector) {
    normalized.vector = vector;
  }
  const description = getTrimmedString(vulnerability.description);
  if (description) {
    normalized.description = description;
  }
  const published = getTrimmedString(vulnerability.published);
  if (published) {
    normalized.published = published;
  }
  const updated = getTrimmedString(vulnerability.updated);
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
      const ref = getTrimmedString(affected.ref);
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
    Array.from(vulnerabilities2.values()).sort(compareVulnerabilities)
  ]));
};
var isCycloneDxJson = (value) => {
  if (!isRecord(value)) {
    return false;
  }
  const bomFormat = getTrimmedString(value.bomFormat)?.toLowerCase();
  if (bomFormat === "cyclonedx") {
    return true;
  }
  const hasSpecVersion = getTrimmedString(value.specVersion) !== void 0;
  const hasComponents = Array.isArray(value.components);
  const hasVulnerabilities = Array.isArray(value.vulnerabilities);
  const metadata = isRecord(value.metadata) ? value.metadata : null;
  const hasMetadataComponent = isRecord(metadata?.component);
  return hasSpecVersion && (hasComponents || hasVulnerabilities || hasMetadataComponent);
};
var parseCycloneDxJson = (bom, options) => {
  const vulnerabilityIndex = buildVulnerabilityIndex(bom);
  const components = flattenComponents(bom).map((component, index) => {
    const name = getTrimmedString(component.name) ?? `Unnamed component ${index + 1}`;
    const version = getTrimmedString(component.version);
    const componentRef = getTrimmedString(component["bom-ref"]);
    const vulnerabilities = componentRef ? [...vulnerabilityIndex.get(componentRef) ?? []] : [];
    const vulnerabilitySummary = vulnerabilities.length > 0 ? buildVulnerabilitySummary(vulnerabilities) : buildEmptyVulnerabilitySummary();
    const highestSeverity = vulnerabilitySummary.highestSeverity;
    const supplier = isRecord(component.supplier) ? getTrimmedString(component.supplier.name) : void 0;
    const purl = getTrimmedString(component.purl);
    const cpe = getTrimmedString(component.cpe);
    const normalized = {
      cweGroups: buildCweGroups(vulnerabilities),
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
    name: getTrimmedString(metadataComponent?.name) ?? options.source.basename,
    sourcePath: options.source.path
  };
};

// src/infrastructure/parsers/SpdxParser.ts
var isRecord2 = (value) => typeof value === "object" && value !== null;
var getTrimmedString2 = (value) => {
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
    const referenceType = getTrimmedString2(normalizedReference.referenceType)?.toLowerCase();
    if (!referenceType || !matcher(referenceType)) {
      continue;
    }
    const locator = getTrimmedString2(normalizedReference.referenceLocator);
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
  const spdxVersion = getTrimmedString2(value.spdxVersion);
  if (spdxVersion?.toUpperCase().startsWith("SPDX-")) {
    return true;
  }
  const spdxId = getTrimmedString2(value.SPDXID);
  if (spdxId === "SPDXRef-DOCUMENT") {
    return true;
  }
  return Array.isArray(value.packages) && isRecord2(value.creationInfo);
};
var parseSpdxJson = (document, options) => {
  const packages = Array.isArray(document.packages) ? document.packages.filter(isRecord2) : [];
  const components = packages.map((pkg, index) => {
    const name = getTrimmedString2(pkg.name) ?? `Unnamed package ${index + 1}`;
    const version = getTrimmedString2(pkg.versionInfo);
    const purl = getExternalReference(pkg, (referenceType) => referenceType.includes("purl"));
    const cpe = getExternalReference(pkg, (referenceType) => referenceType.includes("cpe"));
    const license = getTrimmedString2(pkg.licenseDeclared) ?? getTrimmedString2(pkg.licenseConcluded);
    const normalized = {
      cweGroups: [],
      id: getTrimmedString2(pkg.SPDXID) ?? `${name}@${version ?? "unknown"}#${index}`,
      name,
      vulnerabilitySummary: buildEmptyVulnerabilitySummary2(),
      vulnerabilities: [],
      vulnerabilityCount: 0
    };
    if (version) {
      normalized.version = version;
    }
    const supplier = getTrimmedString2(pkg.supplier);
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
    name: getTrimmedString2(document.name) ?? options.source.basename,
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

// tests/application/services/SbomImportService.test.ts
var InMemorySbomReader = class {
  constructor(files) {
    this.files = files;
  }
  async exists(path) {
    return Object.prototype.hasOwnProperty.call(this.files, path);
  }
  async read(path) {
    const value = this.files[path];
    if (value === void 0) {
      throw new Error("ENOENT");
    }
    return value;
  }
};
var MutableSbomReader = class extends InMemorySbomReader {
  constructor(mutableFiles) {
    super(mutableFiles);
    this.mutableFiles = mutableFiles;
  }
  delete(path) {
    delete this.mutableFiles[path];
  }
};
var StaticNotePathResolverFactory = class {
  constructor(notePathByKey) {
    this.notePathByKey = notePathByKey;
  }
  createResolver() {
    return {
      resolve: (component) => {
        const keys = [
          component.purl ? `purl:${component.purl.toLowerCase()}` : "",
          component.cpe ? `cpe:${component.cpe.toLowerCase()}` : "",
          component.version ? `name-version:${component.name.toLowerCase()}@${component.version.toLowerCase()}` : "",
          `name:${component.name.toLowerCase()}`
        ].filter(Boolean);
        for (const key of keys) {
          const notePath = this.notePathByKey[key];
          if (notePath) {
            return notePath;
          }
        }
        return null;
      }
    };
  }
};
var createSbomConfig = (overrides = {}) => ({
  contentHash: "",
  enabled: true,
  id: "sbom-1",
  label: "Primary SBOM",
  lastImportedAt: 0,
  path: "reports/sbom.json",
  ...overrides
});
test("loads CycloneDX components into runtime cache, normalizes names, and deduplicates by original name", async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    "reports/sbom.json": JSON.stringify({
      bomFormat: "CycloneDX",
      metadata: {
        component: {
          name: "platform-api"
        }
      },
      components: [
        { name: "platform-api" },
        { name: "apache-tomcat-10.1.31" },
        { name: "apache-tomcat-10.1.31" }
      ]
    })
  }));
  const result = await service.loadSbom(createSbomConfig());
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }
  assert.equal(result.state.components.length, 2);
  assert.equal(result.state.document.format, "cyclonedx");
  assert.equal(result.state.components[0]?.normalizedName, "Apache Tomcat 10.1.31");
  assert.equal(result.state.components[1]?.normalizedName, "Platform Api");
  assert.equal(typeof result.state.hash, "string");
  assert.equal(service.getRuntimeState("sbom-1")?.components.length, 2);
});
test("loads SPDX package metadata through the shared parser", async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    "reports/sbom.spdx.json": JSON.stringify({
      SPDXID: "SPDXRef-DOCUMENT",
      name: "Primary SPDX Document",
      packages: [
        {
          SPDXID: "SPDXRef-Package-portal-web",
          externalRefs: [
            {
              referenceLocator: "pkg:npm/portal-web@1.2.3",
              referenceType: "purl"
            }
          ],
          licenseDeclared: "MIT",
          name: "portal-web",
          supplier: "Organization: Example Co",
          versionInfo: "1.2.3"
        }
      ],
      spdxVersion: "SPDX-2.3"
    })
  }));
  const result = await service.loadSbom(createSbomConfig({
    path: "reports/sbom.spdx.json"
  }));
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }
  assert.equal(result.state.document.format, "spdx");
  assert.equal(result.state.document.components[0]?.purl, "pkg:npm/portal-web@1.2.3");
  assert.equal(result.state.components[0]?.normalizedName, "Portal Web");
});
test("resolves component note paths during SBOM import when a resolver factory is configured", async () => {
  const service = new SbomImportService(
    new InMemorySbomReader({
      "reports/sbom.spdx.json": JSON.stringify({
        SPDXID: "SPDXRef-DOCUMENT",
        packages: [
          {
            SPDXID: "SPDXRef-Package-portal-web",
            externalRefs: [
              {
                referenceLocator: "pkg:npm/portal-web@1.2.3",
                referenceType: "purl"
              }
            ],
            name: "portal-web",
            versionInfo: "1.2.3"
          }
        ],
        spdxVersion: "SPDX-2.3"
      })
    }),
    void 0,
    new StaticNotePathResolverFactory({
      "purl:pkg:npm/portal-web@1.2.3": "Components/Portal Web.md"
    })
  );
  const result = await service.loadSbom(createSbomConfig({
    path: "reports/sbom.spdx.json"
  }));
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }
  assert.equal(result.state.document.components[0]?.notePath, "Components/Portal Web.md");
});
test("returns cached runtime data when a later forced load fails", async () => {
  const reader = new MutableSbomReader({
    "reports/sbom.json": JSON.stringify({ components: [{ name: "portal-web" }] })
  });
  const service = new SbomImportService(reader);
  const config = createSbomConfig();
  const initialLoad = await service.loadSbom(config);
  assert.equal(initialLoad.success, true);
  reader.delete("reports/sbom.json");
  const failed = await service.loadSbom(config, { force: true });
  assert.equal(failed.success, false);
  assert.equal(failed.cachedState?.components[0]?.originalName, "portal-web");
});
test("reports file hash status without mutating the runtime cache", async () => {
  const raw = JSON.stringify({ components: [{ name: "widget" }] });
  const service = new SbomImportService(new InMemorySbomReader({
    "reports/sbom.json": raw
  }));
  const loaded = await service.loadSbom(createSbomConfig());
  assert.equal(loaded.success, true);
  if (!loaded.success) {
    return;
  }
  const unchanged = await service.getFileChangeStatus(createSbomConfig({
    contentHash: loaded.state.hash
  }));
  assert.equal(unchanged.status, "unchanged");
  const changedService = new SbomImportService(new InMemorySbomReader({
    "reports/sbom.json": JSON.stringify({ components: [{ name: "widget" }, { name: "api-gateway" }] })
  }));
  const changed = await changedService.getFileChangeStatus(createSbomConfig({
    contentHash: loaded.state.hash
  }));
  assert.equal(changed.status, "changed");
});
test("returns a safe failure for missing files", async () => {
  const service = new SbomImportService(new InMemorySbomReader({}));
  const result = await service.loadSbom(createSbomConfig());
  assert.equal(result.success, false);
  assert.equal(result.error, "ENOENT");
  assert.equal(service.getRuntimeState("sbom-1"), null);
});
test("validates readable supported SBOM JSON files before they are attached", async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    "reports/sbom.json": JSON.stringify({
      bomFormat: "CycloneDX",
      components: [{ name: "portal-web" }, { name: "api-gateway" }]
    })
  }));
  const result = await service.validateSbomPath("reports/sbom.json");
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }
  assert.equal(result.normalizedPath, "reports/sbom.json");
  assert.equal(result.componentCount, 2);
});
test("validates SPDX JSON files before they are attached", async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    "reports/sbom.spdx.json": JSON.stringify({
      SPDXID: "SPDXRef-DOCUMENT",
      packages: [
        { name: "portal-web" },
        { name: "api-gateway" }
      ],
      spdxVersion: "SPDX-2.3"
    })
  }));
  const result = await service.validateSbomPath("reports/sbom.spdx.json");
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }
  assert.equal(result.componentCount, 2);
});
test("rejects JSON files that are not a supported SBOM format", async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    "reports/notes.json": JSON.stringify({
      title: "not an sbom"
    })
  }));
  const result = await service.validateSbomPath("reports/notes.json");
  assert.equal(result.success, false);
  assert.equal(
    result.error,
    'Unsupported SBOM JSON format in "reports/notes.json". Supported formats: CycloneDX JSON and SPDX JSON.'
  );
});
var createDeferred = () => {
  let resolve;
  const promise = new Promise((nextResolve) => {
    resolve = nextResolve;
  });
  return {
    promise,
    resolve
  };
};
var SequencedSbomReader = class {
  constructor() {
    this.reads = [];
  }
  enqueueRead(read) {
    this.reads.push(read);
  }
  async exists() {
    return true;
  }
  async read() {
    const nextRead = this.reads.shift();
    if (!nextRead) {
      throw new Error("unexpected read");
    }
    return nextRead.promise;
  }
};
test("does not allow an older asynchronous SBOM load to overwrite a newer runtime state", async () => {
  const reader = new SequencedSbomReader();
  const firstRead = createDeferred();
  const secondRead = createDeferred();
  reader.enqueueRead(firstRead);
  reader.enqueueRead(secondRead);
  const service = new SbomImportService(reader);
  const config = createSbomConfig();
  const firstLoadPromise = service.loadSbom(config, { force: true });
  const secondLoadPromise = service.loadSbom(config, { force: true });
  secondRead.resolve(JSON.stringify({
    bomFormat: "CycloneDX",
    components: [{ name: "portal-web" }]
  }));
  const secondLoad = await secondLoadPromise;
  assert.equal(secondLoad.success, true);
  firstRead.resolve(JSON.stringify({
    bomFormat: "CycloneDX",
    components: [{ name: "legacy-api" }]
  }));
  const firstLoad = await firstLoadPromise;
  assert.equal(firstLoad.success, true);
  if (!firstLoad.success || !secondLoad.success) {
    return;
  }
  assert.equal(firstLoad.fromCache, true);
  assert.equal(firstLoad.state.components[0]?.originalName, "portal-web");
  assert.equal(service.getRuntimeState(config.id)?.components[0]?.originalName, "portal-web");
});
