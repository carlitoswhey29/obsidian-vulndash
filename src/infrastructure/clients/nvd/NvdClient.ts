import { AuthFailureHttpError, ClientHttpError } from '../../../application/ports/DataSourceError';
import type { HttpResponse, IHttpClient } from '../../../application/ports/HttpClient';
import type { FetchVulnerabilityOptions, FetchVulnerabilityResult, VulnerabilityFeed } from '../../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';
import type { ClientLogger } from '../common/ClientLogger';
import type { RetryPolicy } from '../common/RetryPolicy';
import type { NvdRequestParts, NvdResponse } from './NvdTypes';
import { NvdMapper } from './NvdMapper';
import { NvdRequestBuilder } from './NvdRequestBuilder';
import { filterVulnerabilitiesByDateWindow } from '../../../application/dashboard/PublishedDateWindow';

export interface NvdClientDependencies {
  logger?: ClientLogger;
  retryPolicy?: RetryPolicy;
}

export class NvdClient extends ClientBase implements VulnerabilityFeed {
  private readonly mapper: NvdMapper;
  private readonly requestBuilder: NvdRequestBuilder;

  public constructor(
    httpClient: IHttpClient,
    public readonly id: string,
    public readonly name: string,
    private readonly apiKey: string,
    private readonly controls: FeedSyncControls,
    dateFilterType: 'published' | 'modified' = 'modified',
    dependencies: NvdClientDependencies = {}
  ) {
    super(httpClient, name, controls, dependencies.logger, dependencies.retryPolicy);
    this.mapper = new NvdMapper(this.name);
    this.requestBuilder = new NvdRequestBuilder(this.apiKey, dateFilterType);
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

      // Using the conditional spread to satisfy strict exactOptionalPropertyTypes
      const { response, retriesPerformed: requestRetries } = await this.fetchPage({
        startIndex,
        ...(options.since ? { since: options.since } : {}),
        ...(options.until ? { until: options.until } : {}),
        ...(options.publishedFrom ? { publishedFrom: options.publishedFrom } : {}),
        ...(options.publishedUntil ? { publishedUntil: options.publishedUntil } : {}),
        ...(options.modifiedFrom ? { modifiedFrom: options.modifiedFrom } : {}),
        ...(options.modifiedUntil ? { modifiedUntil: options.modifiedUntil } : {}),
        signal: options.signal,
        operationName: 'fetchVulnerabilities'
      });

      retriesPerformed += requestRetries;
      pagesFetched += 1;

      const items = (response.data.vulnerabilities ?? [])
        .map((item) => item.cve)
        .filter((cve): cve is NonNullable<typeof cve> => Boolean(cve?.id))
        .map((cve) => this.mapper.normalize(cve));
      const filteredItems = options.publishedFrom || options.publishedUntil || options.modifiedFrom || options.modifiedUntil
        ? filterVulnerabilitiesByDateWindow(items, {
          from: options.modifiedFrom ?? options.publishedFrom ?? new Date(0).toISOString(),
          to: options.modifiedUntil ?? options.publishedUntil ?? new Date(8640000000000000).toISOString()
        }, options.modifiedFrom || options.modifiedUntil ? 'modified' : 'published')
        : items;

      for (const item of filteredItems) {
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
    await this.executeRequest(this.requestBuilder.buildValidationRequest(), signal, 'validateConnection');
  }

  private async fetchPage(
    options: {
      startIndex: number;
      since?: string;
      until?: string;
      publishedFrom?: string;
      publishedUntil?: string;
      modifiedFrom?: string;
      modifiedUntil?: string;
      signal: AbortSignal;
      operationName: string;
    }
  ): Promise<{ response: HttpResponse<NvdResponse>; retriesPerformed: number }> {
    const request = this.requestBuilder.buildFetchRequest(options);
    return this.executeRequest(request, options.signal, options.operationName);
  }

  private async executeRequest(
    request: NvdRequestParts,
    signal: AbortSignal,
    operationName: string
  ): Promise<{ response: HttpResponse<NvdResponse>; retriesPerformed: number }> {
    return this.getJsonWithResilience<NvdResponse>({
      context: {
        provider: this.name,
        operation: operationName,
        url: request.url
      },
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
