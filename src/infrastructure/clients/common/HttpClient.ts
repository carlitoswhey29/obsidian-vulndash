import { requestUrl } from 'obsidian';
import type { HttpResponse, IHttpClient } from '../../../application/ports/IHttpClient';
import {
  ClientHttpError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError,
  TimeoutHttpError
} from '../../../application/ports/HttpRequestError';

const parseRetryAfterMs = (retryAfterHeader: string | undefined): number | undefined => {
  if (!retryAfterHeader) return undefined;

  const seconds = Number(retryAfterHeader);
  if (!Number.isNaN(seconds) && Number.isFinite(seconds) && seconds > 0) {
    return seconds * 1_000;
  }

  const retryDate = Date.parse(retryAfterHeader);
  if (Number.isNaN(retryDate)) return undefined;
  return Math.max(retryDate - Date.now(), 0);
};

export class HttpClient implements IHttpClient {
  public async getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<HttpResponse<T>> {
    if (signal.aborted) {
      throw new RetryableNetworkError('Request aborted before execution', { url });
    }

    try {
      const response = await requestUrl({
        url,
        method: 'GET',
        headers,
        throw: false
      });

      const normalizedHeaders = Object.fromEntries(
        Object.entries(response.headers ?? {}).map(([key, value]) => [key.toLowerCase(), String(value)])
      );
      const retryAfterMs = parseRetryAfterMs(normalizedHeaders['retry-after']);

      if (response.status >= 200 && response.status < 300) {
        return { data: response.json as T, status: response.status, headers: normalizedHeaders };
      }

      const metadata = {
        status: response.status,
        headers: normalizedHeaders,
        url,
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {})
      };
      if (response.status === 429) {
        throw new RateLimitHttpError(`Rate limited while requesting ${url}`, metadata);
      }
      if (response.status >= 500) {
        throw new ServerHttpError(`HTTP ${response.status} for ${url}`, metadata);
      }
      throw new ClientHttpError(`HTTP ${response.status} for ${url}`, metadata);
    } catch (error: unknown) {
      if (
        error instanceof ClientHttpError
        || error instanceof ServerHttpError
        || error instanceof RateLimitHttpError
      ) {
        throw error;
      }

      const message = error instanceof Error ? error.message : 'Unknown network error';
      if (message.toLowerCase().includes('timeout')) {
        throw new TimeoutHttpError(`Timeout requesting ${url}`, { url });
      }

      throw new RetryableNetworkError(`Network request failed for ${url}`, { url });
    }
  }
}
