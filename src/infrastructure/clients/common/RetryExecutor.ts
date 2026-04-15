import { HttpRequestError, RateLimitHttpError, RetryableNetworkError, ServerHttpError, TimeoutHttpError } from '../../../application/ports/HttpRequestError';
import type { ClientLogger } from './ClientLogger';
import type { ClientRequestContext } from './ClientRequestContext';
import { computeRetryDelayMs, type RetryPolicy } from './RetryPolicy';

export interface RetryExecutionResult<T> {
  value: T;
  retriesPerformed: number;
}

interface RetryExecutorOptions {
  logger: ClientLogger;
  random?: () => number;
  sleep?: (delayMs: number) => Promise<void>;
}

const sleep = async (delayMs: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
};

const isRetryableHttpError = (error: unknown): error is HttpRequestError =>
  error instanceof RetryableNetworkError
  || error instanceof TimeoutHttpError
  || error instanceof RateLimitHttpError
  || error instanceof ServerHttpError;

export class RetryExecutor {
  private readonly random: () => number;
  private readonly sleep: (delayMs: number) => Promise<void>;

  public constructor(
    private readonly policy: RetryPolicy,
    private readonly options: RetryExecutorOptions
  ) {
    this.random = options.random ?? Math.random;
    this.sleep = options.sleep ?? sleep;
  }

  public async execute<T>(
    contextFactory: (attemptNumber: number) => ClientRequestContext,
    request: (attemptNumber: number) => Promise<T>
  ): Promise<RetryExecutionResult<T>> {
    let retriesPerformed = 0;

    for (let attemptNumber = 1; attemptNumber <= this.policy.maxAttempts; attemptNumber += 1) {
      const context = contextFactory(attemptNumber);
      this.options.logger.requestStart(context);

      try {
        const value = await request(attemptNumber);
        const status = this.extractStatus(value);
        this.options.logger.requestSuccess(context, status);
        return { value, retriesPerformed };
      } catch (error: unknown) {
        this.options.logger.requestFailure(context, {
          errorName: error instanceof Error ? error.name : 'UnknownError',
          message: error instanceof Error ? error.message : 'Unknown request failure',
          ...(error instanceof HttpRequestError && error.metadata.status !== undefined
            ? { status: error.metadata.status }
            : {})
        });

        if (!isRetryableHttpError(error) || attemptNumber >= this.policy.maxAttempts) {
          throw error;
        }

        retriesPerformed += 1;
        const delayMs = computeRetryDelayMs(
          this.policy,
          attemptNumber,
          error.metadata.retryAfterMs,
          this.random
        );

        this.options.logger.requestRetry(context, {
          errorName: error.name,
          message: error.message,
          delayMs,
          ...(error.metadata.status !== undefined ? { status: error.metadata.status } : {})
        });

        await this.sleep(delayMs);
      }
    }

    throw new Error('RetryExecutor exhausted attempts without returning a result.');
  }

  private extractStatus<T>(value: T): number {
    if (
      typeof value === 'object'
      && value !== null
      && 'status' in value
      && typeof (value as { status: unknown }).status === 'number'
    ) {
      return (value as { status: number }).status;
    }

    return 200;
  }
}
