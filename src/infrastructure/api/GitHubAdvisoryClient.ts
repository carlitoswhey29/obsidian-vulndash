import type { VulnerabilityFeed } from '../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import { HttpClient } from './HttpClient';

type GitHubAdvisoryItem = {
    ghsa_id?: string;
    summary?: string;
    description?: string;
    published_at?: string;
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

export class GitHubAdvisoryClient implements VulnerabilityFeed {
  public readonly name = 'GitHub';

  public constructor(private readonly httpClient: HttpClient, private readonly token: string) {}

  public async fetchVulnerabilities(signal: AbortSignal): Promise<Vulnerability[]> {
    const headers: Record<string, string> = {
      Accept: 'application/vnd.github+json'
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    const data = await this.httpClient.getJson<GitHubSecurityResponse>(
      'https://api.github.com/advisories?per_page=25',
      headers,
      signal
    );

    const advisories = Array.isArray(data) ? data : (data.items ?? []);

    return advisories.map((advisory) => {
      const score = advisory.cvss?.score ?? severityToScore(advisory.severity);
      const summary = advisory.description ?? advisory.summary ?? 'No summary provided';

      return {
        id: sanitizeText(advisory.ghsa_id ?? 'unknown'),
        source: this.name,
        title: sanitizeText(advisory.summary ?? advisory.ghsa_id ?? 'GitHub Advisory'),
        summary: sanitizeMarkdown(summary),
        publishedAt: advisory.published_at ?? new Date(0).toISOString(),
        cvssScore: score,
        severity: classifySeverity(score),
        references: [sanitizeUrl(advisory.html_url ?? '')].filter(Boolean),
        affectedProducts: (advisory.vulnerabilities ?? [])
          .map((v) => sanitizeText(v.package?.name ?? ''))
          .filter(Boolean)
      } satisfies Vulnerability;
    });
  }
}
