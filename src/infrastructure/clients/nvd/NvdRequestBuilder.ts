import {
  NVD_BASE_URL,
  NVD_RESULTS_PER_PAGE,
  validateApiKey,
  validateDateRange,
  validatePublishedDateRange,
  validateStartIndex
} from './NvdValidators';
import type { NvdRequestParts, NvdRequestQuery } from './NvdTypes';

export class NvdRequestBuilder {
  public constructor(private readonly apiKey?: string) {}

  public buildFetchRequest(
    options: {
      since?: string;
      until?: string;
      publishedFrom?: string;
      publishedUntil?: string;
      startIndex: number;
    }
  ): NvdRequestParts {
    const safeQuery = this.buildFetchQuery(options);

    return {
      url: this.buildUrl(safeQuery),
      headers: this.buildHeaders()
    };
  }

  public buildValidationRequest(): NvdRequestParts {
    return {
      url: this.buildUrl({ startIndex: 0 }),
      headers: this.buildHeaders()
    };
  }

  private buildFetchQuery(options: {
    since?: string;
    until?: string;
    publishedFrom?: string;
    publishedUntil?: string;
    startIndex: number;
  }): NvdRequestQuery {
    const safeStartIndex = validateStartIndex(options.startIndex);
    const safeDateRange = validateDateRange(options.since, options.until);
    const safePublishedDateRange = validatePublishedDateRange(options.publishedFrom, options.publishedUntil);

    return {
      startIndex: safeStartIndex,
      ...safeDateRange,
      ...safePublishedDateRange
    };
  }

  private buildUrl(query: NvdRequestQuery): string {
    const params = new URLSearchParams({
      resultsPerPage: String(NVD_RESULTS_PER_PAGE),
      startIndex: String(query.startIndex)
    });

    if (query.since) {
      params.set('lastModStartDate', query.since);
    }

    if (query.until) {
      params.set('lastModEndDate', query.until);
    }

    if (query.publishedFrom) {
      params.set('pubStartDate', query.publishedFrom);
    }

    if (query.publishedUntil) {
      params.set('pubEndDate', query.publishedUntil);
    }

    return `${NVD_BASE_URL}?${params.toString()}`;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers.apiKey = validateApiKey(this.apiKey);
    }

    return headers;
  }
}
