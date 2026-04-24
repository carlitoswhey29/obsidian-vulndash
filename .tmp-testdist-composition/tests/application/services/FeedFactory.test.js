// tests/application/services/FeedFactory.test.ts
import test from "node:test";
import assert from "node:assert/strict";

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

// src/application/ports/DataSourceError.ts
var HttpRequestError = class extends Error {
  constructor(name, message, retryable, metadata) {
    super(message);
    this.name = name;
    this.retryable = retryable;
    this.metadata = metadata;
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

// src/domain/value-objects/CvssScore.ts
var classifySeverity = (score) => {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "NONE";
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
var sleep = async (delayMs) => {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
};
var isRetryableHttpRequestError = (error) => error instanceof HttpRequestError && error.retryable;
var RetryExecutor = class {
  constructor(policy, logger, dependencies = {}) {
    this.logger = logger;
    this.policy = normalizeRetryPolicy(policy);
    this.random = dependencies.random ?? Math.random;
    this.sleep = dependencies.sleep ?? sleep;
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
var createRetryPolicyFromControls = (controls2) => normalizeRetryPolicy({
  maxAttempts: Math.max(1, (controls2?.retryCount ?? 0) + 1),
  baseDelayMs: controls2?.backoffBaseMs ?? DEFAULT_RETRY_POLICY.baseDelayMs,
  maxDelayMs: DEFAULT_RETRY_POLICY.maxDelayMs,
  jitter: DEFAULT_RETRY_POLICY.jitter
});
var ClientBase = class {
  constructor(httpClient2, providerOrLogger, controlsOrRetryPolicy, logger, retryPolicy) {
    this.httpClient = httpClient2;
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
  constructor(httpClient2, id, name, token, controls2) {
    super(httpClient2, name, controls2);
    this.id = id;
    this.name = name;
    this.token = token;
    this.controls = controls2;
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
  constructor(httpClient2, id, name, token, repoPath, controls2) {
    super(httpClient2, name, controls2);
    this.id = id;
    this.name = name;
    this.token = token;
    this.controls = controls2;
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
  constructor(httpClient2, id, name, url, token, authHeaderName, controls2) {
    super(httpClient2, name, controls2);
    this.id = id;
    this.name = name;
    this.url = url;
    this.token = token;
    this.authHeaderName = authHeaderName;
    this.controls = controls2;
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
  constructor(httpClient2, id, name, apiKey, controls2, dateFilterType = "modified", dependencies = {}) {
    super(httpClient2, name, controls2, dependencies.logger, dependencies.retryPolicy);
    this.id = id;
    this.name = name;
    this.apiKey = apiKey;
    this.controls = controls2;
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

// src/application/pipeline/PipelineTypes.ts
var buildVulnerabilityCacheKey = (vulnerability) => `${vulnerability.source}:${vulnerability.id}`;
var compareVulnerabilitiesDeterministically = (left, right) => right.publishedAt.localeCompare(left.publishedAt) || right.updatedAt.localeCompare(left.updatedAt) || left.source.localeCompare(right.source) || left.id.localeCompare(right.id) || left.title.localeCompare(right.title);
var sortVulnerabilitiesDeterministically = (vulnerabilities) => Array.from(vulnerabilities).sort(compareVulnerabilitiesDeterministically);

// src/infrastructure/storage/VulnCacheSchema.ts
var buildPersistedVulnerabilityKey = (sourceId, vulnerabilityId) => `${sourceId.trim()}::${vulnerabilityId.trim()}`;

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
  constructor(httpClient2, queryCache, getPurls, controls2, config) {
    super(httpClient2, config.name, controls2);
    this.queryCache = queryCache;
    this.getPurls = getPurls;
    this.controls = controls2;
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
var buildFeedsFromConfig = (configs, httpClient2, controls2, dependencies = {}) => {
  const feeds = [];
  for (const config of configs) {
    if (!config.enabled) {
      continue;
    }
    switch (config.type) {
      case FEED_TYPES.NVD: {
        feeds.push(new NvdClient(
          httpClient2,
          config.id,
          config.name,
          config.apiKey ?? config.token ?? "",
          controls2,
          config.dateFilterType
          // Pass the setting here
        ));
        break;
      }
      case FEED_TYPES.GITHUB_ADVISORY: {
        feeds.push(new GitHubAdvisoryClient(httpClient2, config.id, config.name, config.token ?? "", controls2));
        break;
      }
      case FEED_TYPES.GITHUB_REPO: {
        const repoPath = config.repoPath.trim();
        if (!repoPath) {
          console.warn("[vulndash.feed.invalid]", { id: config.id, type: config.type, reason: "missing_repo_path" });
          break;
        }
        feeds.push(new GitHubRepoClient(httpClient2, config.id, config.name, config.token ?? "", repoPath, controls2));
        break;
      }
      case FEED_TYPES.GENERIC_JSON: {
        const url = config.url.trim();
        if (!url) {
          console.warn("[vulndash.feed.invalid]", { id: config.id, type: config.type, reason: "missing_url" });
          break;
        }
        feeds.push(new GenericJsonFeedClient(
          httpClient2,
          config.id,
          config.name,
          url,
          config.token ?? "",
          config.authHeaderName ?? "Authorization",
          controls2
        ));
        break;
      }
      case FEED_TYPES.OSV: {
        if (!dependencies.osvQueryCache || !dependencies.getPurls) {
          console.warn("[vulndash.feed.invalid]", { id: config.id, type: config.type, reason: "missing_osv_dependencies" });
          break;
        }
        feeds.push(new OsvFeedClient(
          httpClient2,
          dependencies.osvQueryCache,
          dependencies.getPurls,
          controls2,
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

// tests/application/services/FeedFactory.test.ts
var httpClient = {
  async getJson() {
    throw new Error("not_implemented");
  }
};
var controls = {
  maxPages: 2,
  maxItems: 25,
  retryCount: 1,
  backoffBaseMs: 5,
  overlapWindowMs: 6e4,
  bootstrapLookbackMs: 36e5,
  debugHttpMetadata: false
};
test("builds only enabled feeds and skips invalid config entries", () => {
  const configs = [
    { id: BUILT_IN_FEEDS.NVD.id, name: BUILT_IN_FEEDS.NVD.name, type: FEED_TYPES.NVD, enabled: true, apiKey: "k" },
    { id: "github-default", name: "GitHub", type: FEED_TYPES.GITHUB_ADVISORY, enabled: false, token: "x" },
    { id: "repo-feed", name: "Repo feed", type: FEED_TYPES.GITHUB_REPO, enabled: true, repoPath: "Owner/Repo", token: "x" },
    { id: "generic-invalid", name: "Custom", type: FEED_TYPES.GENERIC_JSON, enabled: true, url: "   " },
    {
      id: BUILT_IN_FEEDS.OSV.id,
      name: BUILT_IN_FEEDS.OSV.name,
      type: FEED_TYPES.OSV,
      enabled: true,
      cacheTtlMs: 216e5,
      negativeCacheTtlMs: 36e5,
      requestTimeoutMs: 15e3,
      maxConcurrentBatches: 4,
      osvEndpointUrl: "https://api.osv.dev/v1/querybatch",
      osvMaxBatchSize: 1e3
    }
  ];
  const feeds = buildFeedsFromConfig(configs, httpClient, controls);
  assert.equal(feeds.length, 2);
  assert.deepEqual(feeds.map((feed) => feed.id), [BUILT_IN_FEEDS.NVD.id, "repo-feed"]);
});
test("builds an OSV feed when runtime dependencies are provided", async () => {
  const configs = [
    {
      id: BUILT_IN_FEEDS.OSV.id,
      name: BUILT_IN_FEEDS.OSV.name,
      type: FEED_TYPES.OSV,
      enabled: true,
      cacheTtlMs: 216e5,
      negativeCacheTtlMs: 36e5,
      requestTimeoutMs: 15e3,
      maxConcurrentBatches: 4,
      osvEndpointUrl: "https://api.osv.dev/v1/querybatch",
      osvMaxBatchSize: 1e3
    }
  ];
  const seenPurls = [];
  const savedRecords = [];
  let getPurlsCalls = 0;
  let requestBody;
  const osvQueryCache = {
    async loadComponentQueries() {
      return /* @__PURE__ */ new Map();
    },
    async saveComponentQueries(records) {
      savedRecords.push([...records]);
    },
    async markComponentQueriesSeen(purls) {
      seenPurls.push([...purls]);
    },
    async pruneOrphanedComponentQueries() {
      return 0;
    },
    async pruneExpiredComponentQueries() {
      return 0;
    },
    async loadVulnerabilitiesByCacheKeys() {
      return [];
    }
  };
  const osvHttpClient = {
    ...httpClient,
    async postJson(_url, body) {
      requestBody = body;
      return {
        data: {
          results: [{}]
        },
        headers: {},
        status: 200
      };
    }
  };
  const feeds = buildFeedsFromConfig(configs, osvHttpClient, controls, {
    getPurls: async () => {
      getPurlsCalls += 1;
      return ["pkg:npm/example@1.2.3"];
    },
    osvQueryCache
  });
  assert.equal(feeds.length, 1);
  assert.ok(feeds[0] instanceof OsvFeedClient);
  const result = await feeds[0].fetchVulnerabilities({
    signal: new AbortController().signal
  });
  assert.equal(getPurlsCalls, 1);
  assert.deepEqual(seenPurls, [["pkg:npm/example@1.2.3"]]);
  assert.deepEqual(requestBody, {
    queries: [
      {
        package: {
          purl: "pkg:npm/example@1.2.3"
        }
      }
    ]
  });
  assert.equal(result.vulnerabilities.length, 0);
  assert.equal(savedRecords.length, 1);
  assert.equal(savedRecords[0]?.[0]?.resultState, "miss");
});
test("building an OSV feed does not affect existing feed construction", () => {
  const configs = [
    { id: BUILT_IN_FEEDS.NVD.id, name: BUILT_IN_FEEDS.NVD.name, type: FEED_TYPES.NVD, enabled: true, apiKey: "k" },
    { id: "github-default", name: "GitHub", type: FEED_TYPES.GITHUB_ADVISORY, enabled: true, token: "x" },
    {
      id: BUILT_IN_FEEDS.OSV.id,
      name: BUILT_IN_FEEDS.OSV.name,
      type: FEED_TYPES.OSV,
      enabled: true,
      cacheTtlMs: 216e5,
      negativeCacheTtlMs: 36e5,
      requestTimeoutMs: 15e3,
      maxConcurrentBatches: 4,
      osvEndpointUrl: "https://api.osv.dev/v1/querybatch",
      osvMaxBatchSize: 1e3
    }
  ];
  const feeds = buildFeedsFromConfig(configs, httpClient, controls, {
    getPurls: async () => ["pkg:npm/example@1.2.3"],
    osvQueryCache: {
      async loadComponentQueries() {
        return /* @__PURE__ */ new Map();
      },
      async saveComponentQueries() {
      },
      async markComponentQueriesSeen() {
      },
      async pruneOrphanedComponentQueries() {
        return 0;
      },
      async pruneExpiredComponentQueries() {
        return 0;
      },
      async loadVulnerabilitiesByCacheKeys() {
        return [];
      }
    }
  });
  assert.deepEqual(feeds.map((feed) => feed.id), [BUILT_IN_FEEDS.NVD.id, "github-default", BUILT_IN_FEEDS.OSV.id]);
});
