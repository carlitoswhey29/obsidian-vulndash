import type { HttpResponse, IHttpClient } from '../../../application/ports/IHttpClient';
import type { ClientLogger } from './ClientLogger';
import { consoleClientLogger } from './ClientLogger';
import { sanitizeHeadersForLogging } from './HeaderSanitizer';
import { RetryExecutor } from './RetryExecutor';
import { DEFAULT_RETRY_POLICY, normalizeRetryPolicy } from './RetryPolicy';

export interface FeedSyncControls {
  maxPages: number;
  maxItems: number;
  retryCount?: number;
  backoffBaseMs?: number;
}

export abstract class ClientBase {
  private readonly retryExecutor: RetryExecutor;

  protected constructor(
    protected readonly httpClient: IHttpClient,
    private readonly providerName: string,
    controls: FeedSyncControls,
    logger: ClientLogger = consoleClientLogger
  ) {
    this.retryExecutor = new RetryExecutor(
      normalizeRetryPolicy({
        maxAttempts: (controls.retryCount ?? 0) + 1,
        baseDelayMs: controls.backoffBaseMs ?? DEFAULT_RETRY_POLICY.baseDelayMs,
        maxDelayMs: DEFAULT_RETRY_POLICY.maxDelayMs,
        jitter: DEFAULT_RETRY_POLICY.jitter
      }),
      { logger }
    );
  }

  protected async executeGetJson<T>(request: {
    operationName: string;
    url: string;
    headers: Record<string, string>;
    signal: AbortSignal;
    decorateError?: (error: unknown) => unknown;
  }): Promise<{ response: HttpResponse<T>; retriesPerformed: number }> {
    const safeHeaders = sanitizeHeadersForLogging(request.headers);
    const result = await this.retryExecutor.execute(
      (attemptNumber) => ({
        providerName: this.providerName,
        operationName: request.operationName,
        url: request.url,
        safeHeaders,
        attemptNumber
      }),
      async () => {
        try {
          return await this.httpClient.getJson<T>(request.url, request.headers, request.signal);
        } catch (error: unknown) {
          throw request.decorateError ? request.decorateError(error) : error;
        }
      }
    );

    return {
      response: result.value,
      retriesPerformed: result.retriesPerformed
    };
  }
}
