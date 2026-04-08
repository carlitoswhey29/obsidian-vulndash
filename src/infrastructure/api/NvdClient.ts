import type { SecretProvider, VulnerabilityFeed, FetchVulnerabilityOptions, FetchVulnerabilityResult } from '../../application/ports/VulnerabilityFeed';
import type {
  Vulnerability,
  VulnerabilityAffectedPackage,
  VulnerabilityMetadata,
  VulnerabilitySourceUrls
} from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import type { FeedSyncControls } from './GitHubAdvisoryClient';
import { AuthFailureHttpError } from '../../application/ports/HttpRequestError';

interface NvdCvssMetric {
  cvssData?: { baseScore?: number };
}

interface NvdCpeMatch {
  criteria?: string;
  vulnerable?: boolean;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

interface NvdConfigurationNode {
  cpeMatch?: NvdCpeMatch[];
  nodes?: NvdConfigurationNode[];
}

interface NvdCveRecord {
  id?: string;
  published?: string;
  lastModified?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  references?: Array<{ url?: string }>;
  weaknesses?: Array<{ description?: Array<{ lang?: string; value?: string }> }>;
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
    cvssMetricV2?: NvdCvssMetric[];
  };
  configurations?: Array<{ nodes?: NvdConfigurationNode[] }>;
}

interface NvdResponse {
  startIndex?: number;
  resultsPerPage?: number;
  totalResults?: number;
  vulnerabilities?: Array<{
    cve?: NvdCveRecord;
  }>;
}

interface ParsedCpe {
  vendor: string;
  product: string;
  version: string;
}

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

const cleanCpeToken = (token: string): string => {
  if (!token || token === '*' || token === '-') {
    return '';
  }

  return token
    .replace(/\\([\\:*?!])/g, '$1')
    .replace(/_/g, ' ')
    .trim();
};

const buildVersionRange = (match: NvdCpeMatch, version: string): string => {
  const parts = [
    version,
    match.versionStartIncluding ? `>= ${match.versionStartIncluding}` : '',
    match.versionStartExcluding ? `> ${match.versionStartExcluding}` : '',
    match.versionEndIncluding ? `<= ${match.versionEndIncluding}` : '',
    match.versionEndExcluding ? `< ${match.versionEndExcluding}` : ''
  ].filter(Boolean);

  return parts.join(', ');
};

export class NvdClient implements VulnerabilityFeed {
  private readonly productNameNormalizer = new ProductNameNormalizer();

  public constructor(
    private readonly httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly apiKeyProvider: SecretProvider,
    private readonly controls: FeedSyncControls
  ) {}

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const dedup = new Set<string>();
    const collected: Vulnerability[] = [];
    const warnings: string[] = [];
    const seenIndexes = new Set<number>();
    let pagesFetched = 0;
    let startIndex = 0;

    while (pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenIndexes.has(startIndex)) {
        warnings.push('duplicate_next_url');
        break;
      }
      seenIndexes.add(startIndex);

      const url = await this.buildUrl(options.since, options.until, startIndex);
      let data;
      try {
        data = await this.httpClient.getJson<NvdResponse>(url, {}, options.signal);
      } catch (error: unknown) {
        throw this.decorateNvdError(error);
      }
      pagesFetched += 1;

      const items = (data.data.vulnerabilities ?? [])
        .map((item) => item.cve)
        .filter((cve): cve is NonNullable<typeof cve> => Boolean(cve?.id))
        .map((cve) => this.normalize(cve));

      for (const item of items) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }
        const key = `${item.source}:${item.id}`;
        if (dedup.has(key)) continue;
        dedup.add(key);
        collected.push(item);
      }

      const nextStartIndex = (data.data.startIndex ?? startIndex) + (data.data.resultsPerPage ?? items.length);
      if (items.length === 0 || nextStartIndex >= (data.data.totalResults ?? 0)) {
        break;
      }
      startIndex = nextStartIndex;
    }

    if (pagesFetched >= this.controls.maxPages) warnings.push('max_pages_reached');

    return { vulnerabilities: collected, pagesFetched, warnings, retriesPerformed: 0 };
  }

  private async buildUrl(since: string | undefined, until: string | undefined, startIndex: number): Promise<string> {
    const params = new URLSearchParams({
      resultsPerPage: '100',
      startIndex: String(startIndex)
    });
    const apiKey = await this.apiKeyProvider();
    if (apiKey) {
      params.set('apiKey', apiKey);
    }
    if (since) {
      params.set('lastModStartDate', since);
    }
    if (until) {
      params.set('lastModEndDate', until);
    }
    return `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
  }

  public async validateConnection(signal: AbortSignal): Promise<{ ok: boolean; message: string }> {
    try {
      await this.httpClient.getJson<NvdResponse>(await this.buildValidationUrl(), {}, signal);
      return { ok: true, message: `${this.name} connection validated.` };
    } catch (error: unknown) {
      const decorated = this.decorateNvdError(error);
      if (decorated instanceof AuthFailureHttpError) {
        return {
          ok: false,
          message: `${this.name} API key may be expired, revoked, invalid, or missing required permissions.`
        };
      }
      const message = decorated instanceof Error ? decorated.message : 'Unknown validation error';
      return { ok: false, message };
    }
  }

  private async buildValidationUrl(): Promise<string> {
    const params = new URLSearchParams({
      resultsPerPage: '1',
      startIndex: '0'
    });
    const apiKey = await this.apiKeyProvider();
    if (apiKey) {
      params.set('apiKey', apiKey);
    }
    return `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
  }

  private decorateNvdError(error: unknown): unknown {
    if (error instanceof AuthFailureHttpError) {
      return new AuthFailureHttpError(
        error.authFailureReason === 'unauthorized'
          ? 'NVD request unauthorized (401). API key may be expired, revoked, invalid, or missing.'
          : 'NVD request forbidden (403). API key may be missing required permissions.',
        error.metadata,
        error.authFailureReason
      );
    }

    return error;
  }

  private normalize(cve: NvdCveRecord): Vulnerability {
    const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
      ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore
      ?? cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore
      ?? 0;
    const description = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? 'No summary provided';
    const refs = (cve.references ?? []).map((r) => sanitizeUrl(r.url ?? '')).filter(Boolean);
    const cpeMatches = this.collectCpeMatches(cve.configurations ?? []);
    const affectedProducts = cpeMatches
      .map((match) => this.productNameNormalizer.normalize(sanitizeText(match.criteria ?? '')))
      .filter(Boolean);
    const affectedPackages = cpeMatches
      .map((match): VulnerabilityAffectedPackage | null => this.toAffectedPackage(match))
      .filter((affectedPackage): affectedPackage is VulnerabilityAffectedPackage => affectedPackage !== null);
    const cwes = uniqueNonEmpty((cve.weaknesses ?? [])
      .flatMap((weakness) => weakness.description ?? [])
      .filter((descriptionItem) => descriptionItem.lang === 'en')
      .map((descriptionItem) => sanitizeText(descriptionItem.value ?? ''))
      .filter((cwe) => /^CWE-\d+$/i.test(cwe)));
    const vendors = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.vendor ?? ''));
    const packages = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const vulnerableVersionRanges = uniqueNonEmpty(affectedPackages
      .map((affectedPackage) => affectedPackage.vulnerableVersionRange
        ? `${affectedPackage.vendor ? `${affectedPackage.vendor} ` : ''}${affectedPackage.name}: ${affectedPackage.vulnerableVersionRange}`
        : ''));

    const publishedAt = cve.published ?? new Date(0).toISOString();
    const updatedAt = cve.lastModified ?? publishedAt;
    const cveId = sanitizeText(cve.id ?? '');
    const nvdUrl = cveId ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` : '';
    const sourceUrls: VulnerabilitySourceUrls = {};
    if (nvdUrl) sourceUrls.html = nvdUrl;
    const metadata: VulnerabilityMetadata = {};
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
      id: cveId || 'unknown',
      source: this.name,
      title: sanitizeText(cve.id ?? 'Unknown CVE'),
      summary: sanitizeMarkdown(description),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: uniqueNonEmpty([nvdUrl, ...refs]),
      affectedProducts: uniqueNonEmpty(affectedProducts),
      ...(Object.keys(metadata).length > 0 ? { metadata } : {})
    };
  }

  private collectCpeMatches(configurations: NonNullable<NvdCveRecord['configurations']>): NvdCpeMatch[] {
    const matches: NvdCpeMatch[] = [];

    const visitNode = (node: NvdConfigurationNode): void => {
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

  private parseCpe(criteria: string): ParsedCpe {
    const parts = criteria.split(':');
    return {
      vendor: cleanCpeToken(parts[3] ?? ''),
      product: cleanCpeToken(parts[4] ?? ''),
      version: cleanCpeToken(parts[5] ?? '')
    };
  }

  private toAffectedPackage(match: NvdCpeMatch): VulnerabilityAffectedPackage | null {
    const criteria = match.criteria ?? '';
    const parsed = this.parseCpe(criteria);
    const product = this.productNameNormalizer.normalize(parsed.product);

    if (!product) {
      return null;
    }

    const vendor = this.productNameNormalizer.normalize(parsed.vendor);
    const vulnerableVersionRange = buildVersionRange(match, parsed.version);

    return {
      name: product,
      ...(vendor ? { vendor } : {}),
      ...(vulnerableVersionRange ? { vulnerableVersionRange } : {})
    };
  }
}
