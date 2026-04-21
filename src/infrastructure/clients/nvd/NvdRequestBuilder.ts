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
  public constructor(
    private readonly apiKey?: string,
    private readonly dateFilterType: 'published' | 'modified' = 'modified'
  ) {}

  public buildFetchRequest(
    since: string | undefined,
    until: string | undefined,
    startIndex: number
  ): NvdRequestParts {
    const safeQuery = this.buildFetchQuery(since, until, startIndex);

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

  private buildFetchQuery(since?: string, until?: string, startIndex: number = 0): NvdRequestQuery {
    const safeStartIndex = validateStartIndex(startIndex);
    const safeDateRange = validateDateRange(since, until);
    const safePublishedDateRange = validatePublishedDateRange(since, until);

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

    // Select the appropriate NVD API parameter names
    const startParam = this.dateFilterType === 'published' ? 'pubStartDate' : 'lastModStartDate';
    const endParam = this.dateFilterType === 'published' ? 'pubEndDate' : 'lastModEndDate';

    if (query.since) {
      params.set(startParam, query.since);
    }

    if (query.until) {
      params.set(endParam, query.until);
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
