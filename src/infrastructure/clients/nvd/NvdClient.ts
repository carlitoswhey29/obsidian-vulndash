import { AuthFailureHttpError, ClientHttpError } from '../../../application/ports/HttpRequestError';
import type { HttpResponse, IHttpClient } from '../../../application/ports/IHttpClient';
import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';
import type { NvdResponse } from './NvdTypes';
import { NvdMapper } from './NvdMapper';
import { NvdRequestBuilder } from './NvdRequestBuilder';

export class NvdClient extends ClientBase implements VulnerabilityFeed {
  private readonly mapper: NvdMapper;
  private readonly requestBuilder: NvdRequestBuilder;

  public constructor(
    httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly apiKey: string,
    private readonly controls: FeedSyncControls
  ) {
    super(httpClient, name, controls);
    this.mapper = new NvdMapper(this.name);
    this.requestBuilder = new NvdRequestBuilder(this.apiKey);
  }

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const dedup = new Set<string>();
    const collected: Vulnerability[] = [];
    const warnings: string[] = [];
    const seenIndexes = new Set<number>();

    let pagesFetched = 0;
    let retriesPerformed = 0;
    let startIndex = 0;

    while (pagesFetched < this.controls.maxPages && collected.length < this.controls.maxItems) {
      if (seenIndexes.has(startIndex)) {
        warnings.push('duplicate_start_index');
        break;
      }
      seenIndexes.add(startIndex);

      const { response, retriesPerformed: requestRetries } = await this.fetchPage(
        startIndex,
        options.since,
        options.until,
        options.signal,
        'fetchVulnerabilities'
      );
      retriesPerformed += requestRetries;
      pagesFetched += 1;

      const items = (response.data.vulnerabilities ?? [])
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
        (response.data.startIndex ?? startIndex) + (response.data.resultsPerPage ?? items.length);

      if (items.length === 0 || nextStartIndex >= (response.data.totalResults ?? 0)) {
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
      retriesPerformed
    };
  }

  public async validateConnection(signal: AbortSignal): Promise<void> {
    await this.fetchPage(0, undefined, undefined, signal, 'validateConnection');
  }

  private async fetchPage(
    startIndex: number,
    since: string | undefined,
    until: string | undefined,
    signal: AbortSignal,
    operationName: string
  ): Promise<{ response: HttpResponse<NvdResponse>; retriesPerformed: number }> {
    const request = this.requestBuilder.build(since, until, startIndex);
    return this.executeGetJson<NvdResponse>({
      operationName,
      url: request.url,
      headers: request.headers,
      signal,
      decorateError: (error) => this.decorateNvdError(error)
    });
  }

  private decorateNvdError(error: unknown): unknown {
    if (!(error instanceof ClientHttpError)) {
      return error;
    }

    if (error.metadata.status === 401) {
      return new AuthFailureHttpError(
        'NVD request unauthorized (401). Check API key validity for the configured NVD feed.',
        error.metadata
      );
    }

    if (error.metadata.status === 403) {
      return new AuthFailureHttpError(
        this.apiKey
          ? 'NVD request forbidden (403). API key may be invalid, missing required access, or temporarily blocked by the NVD service.'
          : 'NVD request forbidden (403). Configure a valid NVD API key for this feed.',
        error.metadata
      );
    }

    return error;
  }
}
