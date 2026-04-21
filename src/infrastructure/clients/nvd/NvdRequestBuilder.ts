import {
  NVD_BASE_URL,
  NVD_RESULTS_PER_PAGE,
  validateApiKey,
  validateDateRange,
  validateModifiedDateRange,
  validatePublishedDateRange,
  validateStartIndex
} from './NvdValidators';
import type { NvdRequestParts, NvdRequestQuery } from './NvdTypes';

export class NvdRequestBuilder {
  public constructor(
    private readonly apiKey?: string,
    private readonly dateFilterType: 'published' | 'modified' = 'modified'
  ) {}

  public buildFetchRequest(
    options: {
      startIndex: number;
      since?: string;
      until?: string;
      publishedFrom?: string;
      publishedUntil?: string;
      modifiedFrom?: string;
      modifiedUntil?: string;
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
    startIndex: number;
    since?: string;
    until?: string;
    publishedFrom?: string;
    publishedUntil?: string;
    modifiedFrom?: string;
    modifiedUntil?: string;
  }): NvdRequestQuery {
    const safeStartIndex = validateStartIndex(options.startIndex);
    const safeDateRange = validateDateRange(options.since, options.until);
    const safePublishedDateRange = validatePublishedDateRange(options.publishedFrom, options.publishedUntil);
    const safeModifiedDateRange = validateModifiedDateRange(options.modifiedFrom, options.modifiedUntil);

    return {
      startIndex: safeStartIndex,
      ...safeDateRange,
      ...safePublishedDateRange,
      ...safeModifiedDateRange
    };
  }

  private buildUrl(query: NvdRequestQuery): string {
    const params = new URLSearchParams({
      resultsPerPage: String(NVD_RESULTS_PER_PAGE),
      startIndex: String(query.startIndex)
    });

    // Select the appropriate NVD API parameter names
    const startParam = this.dateFilterType === 'published' ? 'pubStartDate' : 'lastModStartDate';
    const endParam = this.dateFilterType === 'published' ? 'pubEndDate' : 'lastModEndDate';

    const effectiveStart = this.dateFilterType === 'published'
      ? (query.publishedFrom ?? query.since)
      : (query.modifiedFrom ?? query.since);
    const effectiveEnd = this.dateFilterType === 'published'
      ? (query.publishedUntil ?? query.until)
      : (query.modifiedUntil ?? query.until);

    if (effectiveStart) {
      params.set(startParam, effectiveStart);
    }

    if (effectiveEnd) {
      params.set(endParam, effectiveEnd);
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
