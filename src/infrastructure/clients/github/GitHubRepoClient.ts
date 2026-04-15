import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../../application/ports/VulnerabilityFeed';
import type { IHttpClient } from '../../../application/ports/IHttpClient';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import { classifySeverity } from '../../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../utils/sanitize';
import type { FeedSyncControls } from './GitHubAdvisoryClient';
import { extractNextLink } from './GitHubAdvisoryClient';

type GitHubRepoAdvisoryItem = {
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

type GitHubRepoAdvisoryResponse = GitHubRepoAdvisoryItem[] | { items?: GitHubRepoAdvisoryItem[] };

const normalizeRepoPath = (repoPath: string): string => repoPath.trim().toLowerCase();

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

export class GitHubRepoClient implements VulnerabilityFeed {
  private readonly normalizedRepoPath: string;

  public constructor(
    private readonly httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly token: string,
    repoPath: string,
    private readonly controls: FeedSyncControls
  ) {
    this.normalizedRepoPath = normalizeRepoPath(repoPath);
  }

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

    const params = new URLSearchParams({ per_page: '100', affects: this.normalizedRepoPath });
    if (options.since) params.set('updated', options.since);
    let nextUrl: string | undefined = `https://api.github.com/advisories?${params.toString()}`;

    while (nextUrl && pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenUrls.has(nextUrl)) {
        warnings.push('duplicate_next_url');
        break;
      }
      seenUrls.add(nextUrl);

      const response = await this.httpClient.getJson<GitHubRepoAdvisoryResponse>(nextUrl, headers, options.signal);
      pagesFetched += 1;

      const advisories = Array.isArray(response.data) ? response.data : (response.data.items ?? []);
      let newItems = 0;
      for (const advisory of advisories) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }

        const normalized = this.normalize(advisory);
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

  private normalize(advisory: GitHubRepoAdvisoryItem): Vulnerability {
    const score = advisory.cvss?.score ?? severityToScore(advisory.severity);
    const summary = advisory.description ?? advisory.summary ?? 'No summary provided';
    const publishedAt = advisory.published_at ?? new Date(0).toISOString();
    const updatedAt = advisory.updated_at ?? publishedAt;
    const source = `GitHub:${this.normalizedRepoPath}`;

    return {
      id: sanitizeText(advisory.ghsa_id ?? 'unknown'),
      source,
      title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? 'GitHub Advisory'),
      summary: sanitizeMarkdown(summary),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: [sanitizeUrl(advisory.html_url ?? '')].filter(Boolean),
      affectedProducts: uniqueNonEmpty((advisory.vulnerabilities ?? [])
        .map((v) => sanitizeText(v.package?.name ?? '')))
    };
  }
}
