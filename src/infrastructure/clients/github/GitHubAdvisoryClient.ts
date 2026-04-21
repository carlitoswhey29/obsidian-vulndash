import { AuthFailureHttpError, ClientHttpError } from '../../../application/ports/DataSourceError';
import type { IHttpClient } from '../../../application/ports/HttpClient';
import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../../application/ports/VulnerabilityFeed';
import type {
  Vulnerability,
  VulnerabilityAffectedPackage,
  VulnerabilityMetadata,
  VulnerabilitySourceUrls
} from '../../../domain/entities/Vulnerability';
import { filterVulnerabilitiesByDateWindow } from '../../../application/dashboard/PublishedDateWindow';
import { classifySeverity } from '../../../domain/value-objects/CvssScore';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../security/sanitize';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';

export type GitHubAdvisoryItem = {
  ghsa_id?: string;
  cve_id?: string | null;
  url?: string;
  summary?: string;
  description?: string;
  published_at?: string;
  updated_at?: string;
  severity?: 'low' | 'moderate' | 'high' | 'critical';
  cvss?: { score?: number };
  html_url?: string;
  repository_advisory_url?: string;
  source_code_location?: string;
  identifiers?: Array<{ type?: string; value?: string }>;
  references?: string[];
  cwes?: Array<{ cwe_id?: string; name?: string }>;
  vulnerabilities?: Array<{
    package?: { ecosystem?: string; name?: string };
    vulnerable_version_range?: string;
    first_patched_version?: { identifier?: string } | null;
    vulnerable_functions?: string[];
    source_code_location?: string;
  }>;
};

type GitHubSecurityResponse = GitHubAdvisoryItem[] | { items?: GitHubAdvisoryItem[] };
const GITHUB_ADVISORIES_ENDPOINT = 'https://api.github.com/advisories';
const GITHUB_API_VERSION = '2022-11-28';

const severityToScore = (severity: string | undefined): number => {
  switch (severity) {
    case 'critical': return 9.5;
    case 'high': return 8.0;
    case 'moderate': return 5.5;
    case 'low': return 2.5;
    default: return 0;
  }
};

const uniqueNonEmpty = (values: string[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];

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

const findIdentifier = (identifiers: string[], prefix: string): string | undefined =>
  identifiers.find((identifier) => identifier.toLowerCase().startsWith(prefix.toLowerCase()));

const deriveVendor = (packageName: string, sourceCodeLocation: string): string => {
  const scopeMatch = packageName.match(/^@([^/]+)\//);
  if (scopeMatch?.[1]) {
    return scopeMatch[1];
  }

  const githubMatch = sourceCodeLocation.match(/^https?:\/\/(?:www\.)?github\.com\/([^/\s]+)/i);
  return githubMatch?.[1] ?? '';
};

export const extractNextLink = (linkHeader: string | undefined): string | undefined => {
  if (!linkHeader) return undefined;
  const segments = linkHeader.split(',');
  for (const segment of segments) {
    const match = segment.match(/<([^>]+)>\s*;\s*rel="([^"]+)"/);
    if (match?.[2] === 'next') {
      return match[1];
    }
  }
  return undefined;
};

export class GitHubAdvisoryClient extends ClientBase implements VulnerabilityFeed {
  public constructor(
    httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly token: string,
    private readonly controls: FeedSyncControls
  ) {
    super(httpClient, name, controls);
  }

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': GITHUB_API_VERSION,
      'User-Agent': 'obsidian-vulndash'
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    const warnings: string[] = [];
    const dedup = new Set<string>();
    const collected: Vulnerability[] = [];
    const seenUrls = new Set<string>();
    let pagesFetched = 0;
    let retriesPerformed = 0;
    let nextUrl: string | undefined = this.buildInitialUrl(options.since);

    while (nextUrl && pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenUrls.has(nextUrl)) {
        warnings.push('duplicate_next_url');
        break;
      }
      seenUrls.add(nextUrl);

      const { response, retriesPerformed: requestRetries } = await this.executeGetJson<GitHubSecurityResponse>({
        operationName: 'fetchVulnerabilities',
        url: nextUrl,
        headers,
        signal: options.signal,
        decorateError: (error) => this.decorateGitHubError(error)
      });
      retriesPerformed += requestRetries;
      pagesFetched += 1;
      const advisories = Array.isArray(response.data) ? response.data : (response.data.items ?? []);
      let newItems = 0;

      for (const advisory of advisories) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }
        const normalized = this.normalize(advisory, this.name);
        const filteredBatch = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil
          ? filterVulnerabilitiesByDateWindow([normalized], {
            from: options.modifiedFrom ?? options.publishedFrom ?? new Date(0).toISOString(),
            to: options.modifiedUntil ?? options.publishedUntil ?? new Date(8640000000000000).toISOString()
          }, options.modifiedFrom || options.modifiedUntil ? 'modified' : 'published')
          : [normalized];
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
        warnings.push('no_new_unique_records');
        console.info('[vulndash.github.fetch.page]', {
          source: this.name,
          feedId: this.id,
          page: pagesFetched,
          status: response.status,
          itemCount: advisories.length,
          newUniqueItems: newItems,
          warning: 'no_new_unique_records',
          nextPage: extractNextLink(response.headers.link)
        });
        nextUrl = extractNextLink(response.headers.link);
        continue;
      }

      console.info('[vulndash.github.fetch.page]', {
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

    if (pagesFetched >= this.controls.maxPages) warnings.push('max_pages_reached');

    console.info('[vulndash.github.fetch.complete]', {
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

  protected buildInitialUrl(since: string | undefined): string {
    const params = new URLSearchParams({ per_page: '100' });
    if (since) params.set('since', since);
    return `${GITHUB_ADVISORIES_ENDPOINT}?${params.toString()}`;
  }

  private decorateGitHubError(error: unknown): unknown {
    if (!(error instanceof ClientHttpError)) return error;

    if (error.metadata.status === 401) {
      return new AuthFailureHttpError(
        'GitHub advisories request unauthorized (401). Check token validity for the configured GitHub feed.',
        error.metadata
      );
    }
    if (error.metadata.status === 403) {
      const hasToken = Boolean(this.token);
      return new AuthFailureHttpError(
        hasToken
          ? 'GitHub advisories request forbidden (403). Token may be missing required advisory access permissions or may be rate-limited.'
          : 'GitHub advisories request forbidden (403). Configure a GitHub token to avoid low anonymous rate limits.',
        error.metadata
      );
    }

    return error;
  }

  protected normalize(advisory: GitHubAdvisoryItem, sourceLabel: string): Vulnerability {
    const score = advisory.cvss?.score ?? severityToScore(advisory.severity);
    const summary = advisory.description ?? advisory.summary ?? 'No summary provided';
    const publishedAt = advisory.published_at ?? new Date(0).toISOString();
    const updatedAt = advisory.updated_at ?? publishedAt;
    const identifiers = uniqueNonEmpty((advisory.identifiers ?? [])
      .map((identifier) => sanitizeText(identifier.value ?? '')));
    const ghsaId = sanitizeText(advisory.ghsa_id ?? findIdentifier(identifiers, 'GHSA-') ?? '');
    const cveId = sanitizeText(advisory.cve_id ?? findIdentifier(identifiers, 'CVE-') ?? '');
    const cwes = uniqueNonEmpty((advisory.cwes ?? [])
      .map((cwe) => sanitizeText(cwe.cwe_id ?? ''))
      .filter((cwe) => /^CWE-\d+$/i.test(cwe)));
    const affectedPackages = (advisory.vulnerabilities ?? [])
      .map((vulnerability): VulnerabilityAffectedPackage | null => {
        const packageName = sanitizeText(vulnerability.package?.name ?? '');
        if (!packageName) {
          return null;
        }

        const ecosystem = sanitizeText(vulnerability.package?.ecosystem ?? '');
        const sourceCodeLocation = sanitizeUrl(vulnerability.source_code_location ?? advisory.source_code_location ?? '');
        const vulnerableVersionRange = sanitizeText(vulnerability.vulnerable_version_range ?? '');
        const firstPatchedVersion = sanitizeText(vulnerability.first_patched_version?.identifier ?? '');
        const vulnerableFunctions = uniqueNonEmpty((vulnerability.vulnerable_functions ?? [])
          .map((vulnerableFunction) => sanitizeText(vulnerableFunction)));
        const vendor = sanitizeText(deriveVendor(packageName, sourceCodeLocation));

        return {
          name: packageName,
          ...(ecosystem ? { ecosystem } : {}),
          ...(vendor ? { vendor } : {}),
          ...(sourceCodeLocation ? { sourceCodeLocation } : {}),
          ...(vulnerableVersionRange ? { vulnerableVersionRange } : {}),
          ...(firstPatchedVersion ? { firstPatchedVersion } : {}),
          ...(vulnerableFunctions.length > 0 ? { vulnerableFunctions } : {})
        };
      })
      .filter((vulnerability): vulnerability is VulnerabilityAffectedPackage => vulnerability !== null);
    const packages = uniqueNonEmpty(affectedPackages.map((vulnerability) => vulnerability.name));
    const vendors = uniqueNonEmpty(affectedPackages.map((vulnerability) => vulnerability.vendor ?? ''));
    const vulnerableVersionRanges = uniqueNonEmpty(affectedPackages
      .map((vulnerability) => vulnerability.vulnerableVersionRange
        ? `${vulnerability.name}: ${vulnerability.vulnerableVersionRange}`
        : ''));
    const firstPatchedVersions = uniqueNonEmpty(affectedPackages
      .map((vulnerability) => vulnerability.firstPatchedVersion
        ? `${vulnerability.name}: ${vulnerability.firstPatchedVersion}`
        : ''));
    const vulnerableFunctions = uniqueNonEmpty(affectedPackages
      .flatMap((vulnerability) => vulnerability.vulnerableFunctions ?? []));
    const sourceUrls: VulnerabilitySourceUrls = {};
    const apiUrl = sanitizeUrl(advisory.url ?? '');
    const htmlUrl = sanitizeUrl(advisory.html_url ?? '');
    const repositoryAdvisoryUrl = sanitizeUrl(advisory.repository_advisory_url ?? '');
    const sourceCodeUrl = sanitizeUrl(advisory.source_code_location ?? '');

    if (apiUrl) sourceUrls.api = apiUrl;
    if (htmlUrl) sourceUrls.html = htmlUrl;
    if (repositoryAdvisoryUrl) sourceUrls.repositoryAdvisory = repositoryAdvisoryUrl;
    if (sourceCodeUrl) sourceUrls.sourceCode = sourceCodeUrl;

    const metadata: VulnerabilityMetadata = {};
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
      id: ghsaId || cveId || 'unknown',
      source: sourceLabel,
      title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? 'GitHub Advisory'),
      summary: sanitizeMarkdown(summary),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references,
      affectedProducts: packages,
      ...(Object.keys(metadata).length > 0 ? { metadata } : {})
    };
  }
}
