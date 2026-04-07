import { requestUrl } from 'obsidian';
import type { IHttpClient } from '../../application/ports/IHttpClient';
import { HttpRequestError } from '../../application/ports/HttpRequestError';

const parseRetryAfterMs = (retryAfterHeader: string | undefined): number | undefined => {
  if (!retryAfterHeader) {
    return undefined;
  }

  const seconds = Number(retryAfterHeader);
  if (!Number.isNaN(seconds) && Number.isFinite(seconds) && seconds > 0) {
    return seconds * 1_000;
  }

  const retryDate = Date.parse(retryAfterHeader);
  if (Number.isNaN(retryDate)) {
    return undefined;
  }

  return Math.max(retryDate - Date.now(), 0);
};

export class HttpClient implements IHttpClient {
  public async getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<T> {
    if (signal.aborted) {
      throw new HttpRequestError('Request aborted before execution', false);
    }

    try {
      const response = await requestUrl({
        url,
        method: 'GET',
        headers,
        throw: false
      });

      if (response.status >= 200 && response.status < 300) {
        return response.json as T;
      }

      const retryAfterHeader = response.headers['retry-after'] ?? response.headers['Retry-After'];
      const retryAfterMs = parseRetryAfterMs(retryAfterHeader);
      const retryable = response.status === 429 || response.status >= 500;
      throw new HttpRequestError(`HTTP ${response.status} for ${url}`, retryable, response.status, retryAfterMs);
    } catch (error: unknown) {
      if (error instanceof HttpRequestError) {
        throw error;
      }

      throw new HttpRequestError(
        `Network request failed for ${url}`,
        true
      );
    }
  }
}
