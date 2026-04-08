import { requestUrl } from 'obsidian';
import type { HttpResponse, IHttpClient } from '../../application/ports/IHttpClient';
import {
  AuthFailureHttpError,
  ClientHttpError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError,
  TimeoutHttpError
} from '../../application/ports/HttpRequestError';
import { redactSensitiveString } from '../utils/logger';

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
    const safeUrl = redactSensitiveString(url);
    if (signal.aborted) {
      throw new RetryableNetworkError('Request aborted before execution', { url: safeUrl });
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
        url: safeUrl,
        ...(retryAfterMs !== undefined ? { retryAfterMs } : {})
      };
      if (response.status === 401) {
        throw new AuthFailureHttpError(`Authentication failed while requesting ${safeUrl}`, metadata, 'unauthorized');
      }
      if (response.status === 403 && normalizedHeaders['x-ratelimit-remaining'] === '0') {
        throw new RateLimitHttpError(`Rate limited while requesting ${safeUrl}`, metadata);
      }
      if (response.status === 403) {
        throw new AuthFailureHttpError(`Authorization failed while requesting ${safeUrl}`, metadata, 'forbidden');
      }
      if (response.status === 429) {
        throw new RateLimitHttpError(`Rate limited while requesting ${safeUrl}`, metadata);
      }
      if (response.status >= 500) {
        throw new ServerHttpError(`HTTP ${response.status} for ${safeUrl}`, metadata);
      }
      throw new ClientHttpError(`HTTP ${response.status} for ${safeUrl}`, metadata);
    } catch (error: unknown) {
      if (
        error instanceof AuthFailureHttpError
        || error instanceof ClientHttpError
        || error instanceof ServerHttpError
        || error instanceof RateLimitHttpError
      ) {
        throw error;
      }

      const message = error instanceof Error ? error.message : 'Unknown network error';
      if (message.toLowerCase().includes('timeout')) {
        throw new TimeoutHttpError(`Timeout requesting ${safeUrl}`, { url: safeUrl });
      }

      throw new RetryableNetworkError(`Network request failed for ${safeUrl}`, { url: safeUrl });
    }
  }
}
