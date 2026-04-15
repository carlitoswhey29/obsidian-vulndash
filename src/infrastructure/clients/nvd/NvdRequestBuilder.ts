import {
  NVD_BASE_URL,
  NVD_RESULTS_PER_PAGE,
  validateApiKey,
  validateDateRange,
  validateStartIndex
} from './NvdValidators';

export interface NvdRequestParts {
  url: string;
  headers: Record<string, string>;
}

export class NvdRequestBuilder {
  public constructor(private readonly apiKey?: string) {}

  public build(
    since: string | undefined,
    until: string | undefined,
    startIndex: number
  ): NvdRequestParts {
    const safeStartIndex = validateStartIndex(startIndex);
    const { since: safeSince, until: safeUntil } = validateDateRange(since, until);

    const params = new URLSearchParams({
      resultsPerPage: String(NVD_RESULTS_PER_PAGE),
      startIndex: String(safeStartIndex)
    });

    if (safeSince) {
      params.set('lastModStartDate', safeSince);
    }

    if (safeUntil) {
      params.set('lastModEndDate', safeUntil);
    }

    const headers: Record<string, string> = {};
    if (this.apiKey) {
      headers.apiKey = validateApiKey(this.apiKey);
    }

    return {
      url: `${NVD_BASE_URL}?${params.toString()}`,
      headers
    };
  }
}
