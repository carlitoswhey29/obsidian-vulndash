import { requestUrl } from 'obsidian';
import type { HttpResponse, IHttpClient } from '../../../application/ports/HttpClient';
import {
  ClientHttpError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError,
  TimeoutHttpError
} from '../../../application/ports/DataSourceError';

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

const toAbortMetadata = (url: string) => ({ url });

const throwIfAborted = (signal: AbortSignal, url: string): void => {
  if (signal.aborted) {
    throw new RetryableNetworkError('Request aborted before execution', toAbortMetadata(url));
  }
};

const waitForAbort = (signal: AbortSignal, url: string): Promise<never> =>
  new Promise<never>((_, reject) => {
    const onAbort = (): void => {
      signal.removeEventListener('abort', onAbort);
      reject(new RetryableNetworkError('Request aborted during execution', toAbortMetadata(url)));
    };

    signal.addEventListener('abort', onAbort, { once: true });
  });

const executeWithAbort = async <T>(url: string, signal: AbortSignal, action: () => Promise<T>): Promise<T> => {
  throwIfAborted(signal, url);
  return Promise.race([
    action(),
    waitForAbort(signal, url)
  ]);
};

const normalizeHeaders = (headers: Record<string, unknown> | undefined): Record<string, string> =>
  Object.fromEntries(
    Object.entries(headers ?? {}).map(([key, value]) => [key.toLowerCase(), String(value)])
  );

const buildHttpErrorMetadata = (
  status: number,
  headers: Record<string, string>,
  url: string
): {
  status: number;
  headers: Record<string, string>;
  url: string;
  retryAfterMs?: number;
} => {
  const retryAfterMs = parseRetryAfterMs(headers['retry-after']);
  return {
    status,
    headers,
    url,
    ...(retryAfterMs !== undefined ? { retryAfterMs } : {})
  };
};

const handleResponse = <T>(
  url: string,
  response: {
    status: number;
    headers?: Record<string, unknown>;
    json: unknown;
  }
): HttpResponse<T> => {
  const normalizedHeaders = normalizeHeaders(response.headers);

  if (response.status >= 200 && response.status < 300) {
    return { data: response.json as T, status: response.status, headers: normalizedHeaders };
  }

  const metadata = buildHttpErrorMetadata(response.status, normalizedHeaders, url);
  if (response.status === 429) {
    throw new RateLimitHttpError(`Rate limited while requesting ${url}`, metadata);
  }
  if (response.status >= 500) {
    throw new ServerHttpError(`HTTP ${response.status} for ${url}`, metadata);
  }
  throw new ClientHttpError(`HTTP ${response.status} for ${url}`, metadata);
};

const normalizeRequestFailure = (error: unknown, url: string): never => {
  if (
    error instanceof ClientHttpError
    || error instanceof ServerHttpError
    || error instanceof RateLimitHttpError
    || error instanceof RetryableNetworkError
  ) {
    throw error;
  }

  const message = error instanceof Error ? error.message : 'Unknown network error';
  if (message.toLowerCase().includes('timeout')) {
    throw new TimeoutHttpError(`Timeout requesting ${url}`, { url });
  }

  throw new RetryableNetworkError(`Network request failed for ${url}`, { url });
};

export class HttpClient implements IHttpClient {
  public async getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<HttpResponse<T>> {
    try {
      const response = await executeWithAbort(url, signal, async () => requestUrl({
        url,
        method: 'GET',
        headers,
        throw: false
      }));

      return handleResponse<T>(url, response);
    } catch (error: unknown) {
      return normalizeRequestFailure(error, url);
    }
  }

  public async postJson<TRequest, TResponse>(
    url: string,
    body: TRequest,
    headers: Record<string, string>,
    signal: AbortSignal
  ): Promise<HttpResponse<TResponse>> {
    try {
      const response = await executeWithAbort(url, signal, async () => requestUrl({
        url,
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        contentType: 'application/json',
        throw: false
      }));

      return handleResponse<TResponse>(url, response);
    } catch (error: unknown) {
      return normalizeRequestFailure(error, url);
    }
  }
}
