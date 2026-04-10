import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, SecretProvider, VulnerabilityFeed } from '../../application/ports/VulnerabilityFeed';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import type { FeedSyncControls } from './GitHubAdvisoryClient';
import { AuthFailureHttpError } from '../../application/ports/HttpRequestError';

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
    private readonly tokenProvider: SecretProvider,
    private readonly authHeaderName: string,
    private readonly controls: FeedSyncControls
  ) {}

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const warnings: string[] = [];
    const headers: Record<string, string> = {};
    const token = await this.tokenProvider();
    if (token) {
      headers[this.authHeaderName] = token;
    }

    let response;
    try {
      response = await this.httpClient.getJson<GenericFeedResponse>(this.url, headers, options.signal);
    } catch (error: unknown) {
      throw this.decorateGenericError(error);
    }
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

  public async validateConnection(signal: AbortSignal): Promise<{ ok: boolean; message: string }> {
    const headers: Record<string, string> = {};
    const token = await this.tokenProvider();
    if (token) {
      headers[this.authHeaderName] = token;
    }

    try {
      await this.httpClient.getJson<GenericFeedResponse>(this.url, headers, signal);
      return { ok: true, message: `${this.name} connection validated.` };
    } catch (error: unknown) {
      const decorated = this.decorateGenericError(error);
      if (decorated instanceof AuthFailureHttpError) {
        return {
          ok: false,
          message: `${this.name} token may be expired, revoked, invalid, or missing permissions.`
        };
      }
      const message = decorated instanceof Error ? decorated.message : 'Unknown validation error';
      return { ok: false, message };
    }
  }

  private decorateGenericError(error: unknown): unknown {
    if (error instanceof AuthFailureHttpError) {
      return new AuthFailureHttpError(
        error.authFailureReason === 'unauthorized'
          ? 'Generic feed authentication failed (401). Token may be expired, revoked, invalid, or missing.'
          : 'Generic feed authorization failed (403). Token may be missing required permissions.',
        error.metadata,
        error.authFailureReason
      );
    }

    return error;
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
