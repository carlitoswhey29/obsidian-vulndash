import type { HttpResponse, IHttpClient } from '../../../application/ports/IHttpClient';
import type { ClientLogger } from './ClientLogger';
import { NoopClientLogger } from './ClientLogger';
import type { ClientRequestContext } from './ClientRequestContext';
import { sanitizeHeadersForLogs } from './HeaderSanitizer';
import { RetryExecutor } from './RetryExecutor';
import { DEFAULT_RETRY_POLICY, normalizeRetryPolicy, type RetryPolicy } from './RetryPolicy';

export interface FeedSyncControls {
  maxPages: number;
  maxItems: number;
  retryCount?: number;
  backoffBaseMs?: number;
}

interface LegacyExecuteGetJsonRequest {
  operationName: string;
  url: string;
  headers: Record<string, string>;
  signal: AbortSignal;
  decorateError?: (error: unknown) => unknown;
}

const DEFAULT_CLIENT_LOGGER = new NoopClientLogger();

const createRetryPolicyFromControls = (controls: FeedSyncControls | undefined): RetryPolicy =>
  normalizeRetryPolicy({
    maxAttempts: Math.max(1, (controls?.retryCount ?? 0) + 1),
    baseDelayMs: controls?.backoffBaseMs ?? DEFAULT_RETRY_POLICY.baseDelayMs,
    maxDelayMs: DEFAULT_RETRY_POLICY.maxDelayMs,
    jitter: DEFAULT_RETRY_POLICY.jitter
  });

export abstract class ClientBase {
  private readonly logger: ClientLogger;
  private readonly retryExecutor: RetryExecutor;
  private readonly defaultProvider: string | undefined;

  protected constructor(httpClient: IHttpClient, logger?: ClientLogger, retryPolicy?: RetryPolicy);
  protected constructor(httpClient: IHttpClient, provider: string, controls: FeedSyncControls, logger?: ClientLogger);
  protected constructor(
    protected readonly httpClient: IHttpClient,
    providerOrLogger?: string | ClientLogger,
    controlsOrRetryPolicy?: FeedSyncControls | RetryPolicy,
    logger?: ClientLogger
  ) {
    if (typeof providerOrLogger === 'string') {
      this.defaultProvider = providerOrLogger;
      this.logger = logger ?? DEFAULT_CLIENT_LOGGER;
      this.retryExecutor = new RetryExecutor(
        createRetryPolicyFromControls(controlsOrRetryPolicy as FeedSyncControls | undefined),
        this.logger
      );
      return;
    }

    this.defaultProvider = undefined;
    this.logger = providerOrLogger ?? DEFAULT_CLIENT_LOGGER;
    this.retryExecutor = new RetryExecutor(
      normalizeRetryPolicy((controlsOrRetryPolicy as RetryPolicy | undefined) ?? DEFAULT_RETRY_POLICY),
      this.logger
    );
  }

  protected async getJsonWithResilience<T>(
    context: Omit<ClientRequestContext, 'headers' | 'attempt'>,
    url: string,
    headers: Record<string, string>,
    signal: AbortSignal
  ): Promise<HttpResponse<T>> {
    const { response } = await this.executeJsonRequest<T>({
      context,
      url,
      headers,
      signal
    });

    return response;
  }

  protected async executeGetJson<T>(request: LegacyExecuteGetJsonRequest): Promise<{
    response: HttpResponse<T>;
    retriesPerformed: number;
  }> {
    return this.executeJsonRequest<T>({
      context: {
        provider: this.defaultProvider ?? 'unknown',
        operation: request.operationName,
        url: request.url
      },
      url: request.url,
      headers: request.headers,
      signal: request.signal,
      ...(request.decorateError ? { decorateError: request.decorateError } : {})
    });
  }

  private async executeJsonRequest<T>(request: {
    context: Omit<ClientRequestContext, 'headers' | 'attempt'>;
    url: string;
    headers: Record<string, string>;
    signal: AbortSignal;
    decorateError?: (error: unknown) => unknown;
  }): Promise<{ response: HttpResponse<T>; retriesPerformed: number }> {
    const sanitizedHeaders = sanitizeHeadersForLogs(request.headers);
    const baseContext: Omit<ClientRequestContext, 'attempt'> = {
      provider: request.context.provider,
      operation: request.context.operation,
      url: request.url,
      headers: sanitizedHeaders
    };

    let lastAttempt = 1;
    const response = await this.retryExecutor.execute<HttpResponse<T>>(async (attempt) => {
      lastAttempt = attempt;
      const attemptContext: ClientRequestContext = {
        ...baseContext,
        attempt
      };

      this.logger.onRequestStart(attemptContext);

      try {
        const result = await this.httpClient.getJson<T>(request.url, request.headers, request.signal);
        this.logger.onRequestSuccess({
          ...attemptContext,
          status: result.status
        });
        return result;
      } catch (error: unknown) {
        throw request.decorateError ? request.decorateError(error) : error;
      }
    }, baseContext);

    return {
      response,
      retriesPerformed: Math.max(0, lastAttempt - 1)
    };
  }
}
