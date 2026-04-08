import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../application/ports/VulnerabilityFeed';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import type { FeedSyncControls } from './GitHubAdvisoryClient';

type GenericSeverity = 'none' | 'low' | 'medium' | 'high' | 'critical';

interface GenericVulnerabilityRecord {
  id?: string;
  title?: string;
  summary?: string;
  publishedAt?: string;
  updatedAt?: string;
  severity?: GenericSeverity;
  cvssScore?: number;
  references?: string[];
  affectedProducts?: string[];
  source?: string;
}

interface GenericFeedResponse {
  vulnerabilities?: GenericVulnerabilityRecord[];
}

const severityToScore = (severity: GenericSeverity | undefined): number => {
  switch (severity) {
    case 'critical': return 9.5;
    case 'high': return 8;
    case 'medium': return 5;
    case 'low': return 2.5;
    default: return 0;
  }
};

export class GenericJsonFeedClient implements VulnerabilityFeed {
  public constructor(
    private readonly httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly url: string,
    private readonly token: string,
    private readonly authHeaderName: string,
    private readonly controls: FeedSyncControls
  ) {}

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const warnings: string[] = [];
    const headers: Record<string, string> = {};
    if (this.token) {
      headers[this.authHeaderName] = this.token;
    }

    const response = await this.httpClient.getJson<GenericFeedResponse>(this.url, headers, options.signal);
    const records = response.data.vulnerabilities ?? [];
    const vulnerabilities = records
      .slice(0, this.controls.maxItems)
      .map((record) => this.normalize(record));

    if (records.length > this.controls.maxItems) {
      warnings.push('max_items_reached');
    }

    return {
      vulnerabilities,
      pagesFetched: 1,
      warnings,
      retriesPerformed: 0
    };
  }

  private normalize(record: GenericVulnerabilityRecord): Vulnerability {
    const score = typeof record.cvssScore === 'number' ? record.cvssScore : severityToScore(record.severity);
    const source = sanitizeText(record.source ?? `Generic:${this.name}`);
    const publishedAt = sanitizeText(record.publishedAt ?? new Date(0).toISOString());
    const updatedAt = sanitizeText(record.updatedAt ?? publishedAt);

    return {
      id: sanitizeText(record.id ?? 'unknown'),
      source,
      title: sanitizeText(record.title ?? record.id ?? this.name),
      summary: sanitizeMarkdown(record.summary ?? 'No summary provided'),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: (record.references ?? []).map((reference) => sanitizeUrl(reference)).filter(Boolean),
      affectedProducts: (record.affectedProducts ?? []).map((product) => sanitizeText(product)).filter(Boolean)
    };
  }
}
