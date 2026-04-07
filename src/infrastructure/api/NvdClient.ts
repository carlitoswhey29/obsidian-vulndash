import type { VulnerabilityFeed, FetchVulnerabilityOptions, FetchVulnerabilityResult } from '../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import type { FeedSyncControls } from './GitHubAdvisoryClient';

interface NvdResponse {
  totalResults?: number;
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      published?: string;
      lastModified?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      references?: Array<{ url?: string }>;
      metrics?: {
        cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
      };
      configurations?: Array<{ nodes?: Array<{ cpeMatch?: Array<{ criteria?: string }> }> }>;
    };
  }>;
}

export class NvdClient implements VulnerabilityFeed {
  public readonly name = 'NVD';

  public constructor(
    private readonly httpClient: IHttpClient,
    private readonly apiKey: string,
    private readonly controls: FeedSyncControls
  ) {}

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const headers: Record<string, string> = {};
    if (this.apiKey) headers.apiKey = this.apiKey;

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

      const url = this.buildUrl(options.since, startIndex);
      const data = await this.httpClient.getJson<NvdResponse>(url, headers, options.signal);
      pagesFetched += 1;

      const items = (data.data.vulnerabilities ?? [])
        .map((item) => item.cve)
        .filter((cve): cve is NonNullable<typeof cve> => Boolean(cve?.id))
        .map((cve) => this.normalize(cve));

      let newItems = 0;
      for (const item of items) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }
        const key = `${item.source}:${item.id}`;
        if (dedup.has(key)) continue;
        dedup.add(key);
        collected.push(item);
        newItems += 1;
      }

      if (newItems === 0) {
        warnings.push('no_new_unique_records');
        break;
      }

      startIndex += items.length;
      if (items.length === 0 || startIndex >= (data.data.totalResults ?? 0)) {
        break;
      }
    }

    if (pagesFetched >= this.controls.maxPages) warnings.push('max_pages_reached');

    return { vulnerabilities: collected, pagesFetched, warnings, retriesPerformed: 0 };
  }

  private buildUrl(since: string | undefined, startIndex: number): string {
    const params = new URLSearchParams({
      resultsPerPage: '100',
      startIndex: String(startIndex)
    });
    if (since) {
      // NVD incremental mapping: query CVEs changed since cursor.
      params.set('lastModStartDate', since);
    }
    return `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`;
  }

  private normalize(cve: NonNullable<NonNullable<NvdResponse['vulnerabilities']>[number]['cve']>): Vulnerability {
    const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 0;
    const description = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? 'No summary provided';
    const refs = (cve.references ?? []).map((r) => sanitizeUrl(r.url ?? '')).filter(Boolean);
    const affectedProducts = (cve.configurations ?? [])
      .flatMap((config) => config.nodes ?? [])
      .flatMap((node) => node.cpeMatch ?? [])
      .map((m) => sanitizeText(m.criteria ?? ''))
      .filter(Boolean);

    const publishedAt = cve.published ?? new Date(0).toISOString();
    const updatedAt = cve.lastModified ?? publishedAt;

    return {
      id: sanitizeText(cve.id ?? 'unknown'),
      source: this.name,
      title: sanitizeText(cve.id ?? 'Unknown CVE'),
      summary: sanitizeMarkdown(description),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: refs,
      affectedProducts
    };
  }
}
