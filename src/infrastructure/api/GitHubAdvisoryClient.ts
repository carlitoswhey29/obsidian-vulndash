import type { VulnerabilityFeed, FetchVulnerabilityOptions, FetchVulnerabilityResult } from '../../application/ports/VulnerabilityFeed';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';

export interface FeedSyncControls {
  maxPages: number;
  maxItems: number;
}

export type GitHubAdvisoryItem = {
  ghsa_id?: string;
  summary?: string;
  description?: string;
  published_at?: string;
  updated_at?: string;
  severity?: 'low' | 'moderate' | 'high' | 'critical';
  cvss?: { score?: number };
  html_url?: string;
  vulnerabilities?: Array<{ package?: { name?: string } }>;
};

type GitHubSecurityResponse = GitHubAdvisoryItem[] | { items?: GitHubAdvisoryItem[] };

const severityToScore = (severity: string | undefined): number => {
  switch (severity) {
    case 'critical': return 9.5;
    case 'high': return 8.0;
    case 'moderate': return 5.5;
    case 'low': return 2.5;
    default: return 0;
  }
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

export class GitHubAdvisoryClient implements VulnerabilityFeed {
  public constructor(
    private readonly httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly token: string,
    private readonly controls: FeedSyncControls
  ) {}

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json'
    };
    if (this.token) headers.Authorization = `Bearer ${this.token}`;

    const warnings: string[] = [];
    const dedup = new Set<string>();
    const collected: Vulnerability[] = [];
    const seenUrls = new Set<string>();
    let pagesFetched = 0;
    let nextUrl: string | undefined = this.buildInitialUrl(options.since);

    while (nextUrl && pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenUrls.has(nextUrl)) {
        warnings.push('duplicate_next_url');
        break;
      }
      seenUrls.add(nextUrl);

      const response = await this.httpClient.getJson<GitHubSecurityResponse>(nextUrl, headers, options.signal);
      pagesFetched += 1;
      const advisories = Array.isArray(response.data) ? response.data : (response.data.items ?? []);
      let newItems = 0;

      for (const advisory of advisories) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }
        const normalized = this.normalize(advisory, this.name);
        const key = `${normalized.source}:${normalized.id}`;
        if (dedup.has(key)) continue;
        dedup.add(key);
        collected.push(normalized);
        newItems += 1;
      }

      if (newItems === 0) {
        warnings.push('no_new_unique_records');
        break;
      }

      nextUrl = extractNextLink(response.headers.link);
    }

    if (pagesFetched >= this.controls.maxPages) warnings.push('max_pages_reached');

    return {
      vulnerabilities: collected,
      pagesFetched,
      warnings,
      retriesPerformed: 0
    };
  }

  protected buildInitialUrl(since: string | undefined): string {
    const params = new URLSearchParams({ per_page: '100' });
    if (since) params.set('updated', since);
    return `https://api.github.com/advisories?${params.toString()}`;
  }

  protected normalize(advisory: GitHubAdvisoryItem, sourceLabel: string): Vulnerability {
    const score = advisory.cvss?.score ?? severityToScore(advisory.severity);
    const summary = advisory.description ?? advisory.summary ?? 'No summary provided';
    const publishedAt = advisory.published_at ?? new Date(0).toISOString();
    const updatedAt = advisory.updated_at ?? publishedAt;

    return {
      id: sanitizeText(advisory.ghsa_id ?? 'unknown'),
      source: sourceLabel,
      title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? 'GitHub Advisory'),
      summary: sanitizeMarkdown(summary),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: [sanitizeUrl(advisory.html_url ?? '')].filter(Boolean),
      affectedProducts: (advisory.vulnerabilities ?? [])
        .map((v) => sanitizeText(v.package?.name ?? ''))
        .filter(Boolean)
    };
  }
}
