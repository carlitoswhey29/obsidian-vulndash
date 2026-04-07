import type { VulnerabilityFeed } from '../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { classifySeverity } from '../../domain/services/Cvss';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../utils/sanitize';
import type { IHttpClient } from '../../application/ports/IHttpClient';

interface NvdResponse {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      published?: string;
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

  public constructor(private readonly httpClient: IHttpClient, private readonly apiKey: string) {}

  public async fetchVulnerabilities(signal: AbortSignal): Promise<Vulnerability[]> {
    const params = new URLSearchParams({ resultsPerPage: '25' });
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers.apiKey = this.apiKey;
    }

    const data = await this.httpClient.getJson<NvdResponse>(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`,
      headers,
      signal
    );

    return (data.vulnerabilities ?? [])
      .map((item) => item.cve)
      .filter((cve): cve is NonNullable<typeof cve> => Boolean(cve?.id))
      .map((cve) => {
        const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ?? 0;
        const description = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? 'No summary provided';
        const refs = (cve.references ?? []).map((r) => sanitizeUrl(r.url ?? '')).filter(Boolean);
        const affectedProducts = (cve.configurations ?? [])
          .flatMap((config) => config.nodes ?? [])
          .flatMap((node) => node.cpeMatch ?? [])
          .map((m) => sanitizeText(m.criteria ?? ''))
          .filter(Boolean);

        return {
          id: sanitizeText(cve.id ?? 'unknown'),
          source: this.name,
          title: sanitizeText(cve.id ?? 'Unknown CVE'),
          summary: sanitizeMarkdown(description),
          publishedAt: cve.published ?? new Date(0).toISOString(),
          cvssScore: score,
          severity: classifySeverity(score),
          references: refs,
          affectedProducts
        } satisfies Vulnerability;
      });
  }
}
