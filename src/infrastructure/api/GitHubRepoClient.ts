import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, SecretProvider, VulnerabilityFeed } from '../../application/ports/VulnerabilityFeed';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import type { FeedSyncControls } from './GitHubAdvisoryClient';
import { extractNextLink } from './GitHubAdvisoryClient';
import { AuthFailureHttpError } from '../../application/ports/HttpRequestError';

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

export class GitHubRepoClient implements VulnerabilityFeed {
  private readonly normalizedRepoPath: string;

  public constructor(
    private readonly httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly tokenProvider: SecretProvider,
    repoPath: string,
    private readonly controls: FeedSyncControls
  ) {
    this.normalizedRepoPath = normalizeRepoPath(repoPath);
  }

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json'
    };
    const token = await this.tokenProvider();
    if (token) headers.Authorization = `Bearer ${token}`;

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

      let response;
      try {
        response = await this.httpClient.getJson<GitHubRepoAdvisoryResponse>(nextUrl, headers, options.signal);
      } catch (error: unknown) {
        throw this.decorateGitHubRepoError(error);
      }
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

  public async validateConnection(signal: AbortSignal): Promise<{ ok: boolean; message: string }> {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json'
    };
    const token = await this.tokenProvider();
    if (token) headers.Authorization = `Bearer ${token}`;

    try {
      const params = new URLSearchParams({ per_page: '1', affects: this.normalizedRepoPath });
      await this.httpClient.getJson<GitHubRepoAdvisoryResponse>(`https://api.github.com/advisories?${params.toString()}`, headers, signal);
      return { ok: true, message: `${this.name} connection validated.` };
    } catch (error: unknown) {
      const decorated = this.decorateGitHubRepoError(error);
      if (decorated instanceof AuthFailureHttpError) {
        return {
          ok: false,
          message: `${this.name} token may be expired, revoked, invalid, or missing repository advisory permissions.`
        };
      }
      const message = decorated instanceof Error ? decorated.message : 'Unknown validation error';
      return { ok: false, message };
    }
  }

  private decorateGitHubRepoError(error: unknown): unknown {
    if (error instanceof AuthFailureHttpError) {
      return new AuthFailureHttpError(
        error.authFailureReason === 'unauthorized'
          ? 'GitHub repository advisory request unauthorized (401). Token may be expired, revoked, invalid, or missing.'
          : 'GitHub repository advisory request forbidden (403). Token may be missing required advisory permissions, or anonymous access may be blocked.',
        error.metadata,
        error.authFailureReason
      );
    }

    return error;
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
      affectedProducts: (advisory.vulnerabilities ?? [])
        .map((v) => sanitizeText(v.package?.name ?? ''))
        .filter(Boolean)
    };
  }
}
