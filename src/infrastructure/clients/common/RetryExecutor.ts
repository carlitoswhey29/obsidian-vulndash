import { HttpRequestError } from '../../../application/ports/HttpRequestError';
import type { ClientLogger } from './ClientLogger';
import type { ClientRequestContext } from './ClientRequestContext';
import { normalizeRetryPolicy, type RetryPolicy } from './RetryPolicy';

interface RetryExecutorDependencies {
  random?: () => number;
  sleep?: (delayMs: number) => Promise<void>;
}

const sleep = async (delayMs: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
};

const isRetryableHttpRequestError = (error: unknown): error is HttpRequestError =>
  error instanceof HttpRequestError && error.retryable;

export class RetryExecutor {
  private readonly policy: RetryPolicy;
  private readonly random: () => number;
  private readonly sleep: (delayMs: number) => Promise<void>;

  public constructor(
    policy: RetryPolicy,
    private readonly logger: ClientLogger,
    dependencies: RetryExecutorDependencies = {}
  ) {
    this.policy = normalizeRetryPolicy(policy);
    this.random = dependencies.random ?? Math.random;
    this.sleep = dependencies.sleep ?? sleep;
  }

  public async execute<T>(
    action: (attempt: number) => Promise<T>,
    baseContext: Omit<ClientRequestContext, 'attempt'>
  ): Promise<T> {
    for (let attempt = 1; attempt <= this.policy.maxAttempts; attempt += 1) {
      try {
        return await action(attempt);
      } catch (error: unknown) {
        if (!isRetryableHttpRequestError(error) || attempt >= this.policy.maxAttempts) {
          this.logger.onRequestFailure(this.buildContext(baseContext, attempt, error));
          throw error;
        }

        const delayMs = this.computeRetryDelayMs(attempt, error.metadata.retryAfterMs);
        this.logger.onRequestRetry(this.buildContext(baseContext, attempt, error, delayMs));
        await this.sleep(delayMs);
      }
    }

    throw new Error('RetryExecutor exhausted attempts without returning a result.');
  }

  private computeRetryDelayMs(attempt: number, retryAfterMs: number | undefined): number {
    if (typeof retryAfterMs === 'number' && Number.isFinite(retryAfterMs)) {
      return Math.max(0, Math.trunc(retryAfterMs));
    }

    const boundedDelay = Math.min(
      this.policy.baseDelayMs * (2 ** Math.max(0, attempt - 1)),
      this.policy.maxDelayMs
    );

    if (!this.policy.jitter) {
      return boundedDelay;
    }

    const jitterMultiplier = 0.5 + this.random();
    return Math.min(
      this.policy.maxDelayMs,
      Math.max(0, Math.round(boundedDelay * jitterMultiplier))
    );
  }

  private buildContext(
    baseContext: Omit<ClientRequestContext, 'attempt'>,
    attempt: number,
    error: unknown,
    retryDelayMs?: number
  ): ClientRequestContext {
    const errorName = error instanceof Error ? error.name : 'UnknownError';
    const status = error instanceof HttpRequestError ? error.metadata.status : undefined;

    return {
      ...baseContext,
      attempt,
      ...(status !== undefined ? { status } : {}),
      ...(retryDelayMs !== undefined ? { retryDelayMs } : {}),
      errorName
    };
  }
}
