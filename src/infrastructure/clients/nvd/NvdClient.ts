import type { VulnerabilityFeed, FetchVulnerabilityOptions, FetchVulnerabilityResult } from '../../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import type { IHttpClient } from '../../../application/ports/IHttpClient';
import type { FeedSyncControls } from '../github/GitHubAdvisoryClient';
import type { NvdResponse } from './NvdTypes';
import { NvdMapper } from './NvdMapper';
import { NvdRequestBuilder } from './NvdRequestBuilder';

export class NvdClient implements VulnerabilityFeed {
  private readonly mapper: NvdMapper;
  private readonly requestBuilder: NvdRequestBuilder;

  public constructor(
    private readonly httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly apiKey: string,
    private readonly controls: FeedSyncControls
  ) {
    this.mapper = new NvdMapper(this.name);
    this.requestBuilder = new NvdRequestBuilder(this.apiKey);
  }

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

      const request = this.requestBuilder.build(options.since, options.until, startIndex);
      const data = await this.httpClient.getJson<NvdResponse>(request.url, request.headers, options.signal);
      pagesFetched += 1;

      const items = (data.data.vulnerabilities ?? [])
        .map((item) => item.cve)
        .filter((cve): cve is NonNullable<typeof cve> => Boolean(cve?.id))
        .map((cve) => this.mapper.normalize(cve));

      for (const item of items) {
        if (collected.length >= this.controls.maxItems) {
          warnings.push('max_items_reached');
          break;
        }

        const key = `${item.source}:${item.id}`;
        if (dedup.has(key)) {
          continue;
        }

        dedup.add(key);
        collected.push(item);
      }

      const nextStartIndex =
        (data.data.startIndex ?? startIndex) + (data.data.resultsPerPage ?? items.length);

      if (items.length === 0 || nextStartIndex >= (data.data.totalResults ?? 0)) {
        break;
      }

      startIndex = nextStartIndex;
    }

    if (pagesFetched >= this.controls.maxPages) {
      warnings.push('max_pages_reached');
    }

    return {
      vulnerabilities: collected,
      pagesFetched,
      warnings,
      retriesPerformed: 0
    };
  }
}
