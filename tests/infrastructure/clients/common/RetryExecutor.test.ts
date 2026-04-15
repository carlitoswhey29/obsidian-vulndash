import test from 'node:test';
import assert from 'node:assert/strict';
import { ClientHttpError, RateLimitHttpError, RetryableNetworkError } from '../../../../src/application/ports/HttpRequestError';
import { consoleClientLogger } from '../../../../src/infrastructure/clients/common/ClientLogger';
import { RetryExecutor } from '../../../../src/infrastructure/clients/common/RetryExecutor';

test('retries retryable HttpRequestError failures until the request succeeds', async () => {
  const delays: number[] = [];
  let attempts = 0;
  const executor = new RetryExecutor(
    { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 100, jitter: false },
    {
      logger: consoleClientLogger,
      sleep: async (delayMs) => { delays.push(delayMs); }
    }
  );

  const result = await executor.execute(
    (attemptNumber) => ({
      providerName: 'NVD',
      operationName: 'fetchVulnerabilities',
      url: 'https://example.test',
      safeHeaders: {},
      attemptNumber
    }),
    async () => {
      attempts += 1;
      if (attempts < 3) {
        throw new RetryableNetworkError('temporary network issue', { url: 'https://example.test' });
      }
      return { status: 200, value: 'ok' };
    }
  );

  assert.equal(attempts, 3);
  assert.equal(result.retriesPerformed, 2);
  assert.deepEqual(delays, [10, 20]);
});

test('stops immediately on non-retryable HttpRequestError failures', async () => {
  const executor = new RetryExecutor(
    { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 100, jitter: false },
    {
      logger: consoleClientLogger,
      sleep: async () => {}
    }
  );

  await assert.rejects(
    () => executor.execute(
      (attemptNumber) => ({
        providerName: 'NVD',
        operationName: 'fetchVulnerabilities',
        url: 'https://example.test',
        safeHeaders: {},
        attemptNumber
      }),
      async () => {
        throw new ClientHttpError('bad request', { status: 400, url: 'https://example.test' });
      }
    ),
    (error: unknown) => error instanceof ClientHttpError
  );
});

test('honors retryAfterMs when provided by a retryable error', async () => {
  const delays: number[] = [];
  let attempts = 0;
  const executor = new RetryExecutor(
    { maxAttempts: 2, baseDelayMs: 10, maxDelayMs: 100, jitter: false },
    {
      logger: consoleClientLogger,
      sleep: async (delayMs) => { delays.push(delayMs); }
    }
  );

  const result = await executor.execute(
    (attemptNumber) => ({
      providerName: 'GitHub',
      operationName: 'fetchVulnerabilities',
      url: 'https://api.github.com/advisories',
      safeHeaders: {},
      attemptNumber
    }),
    async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new RateLimitHttpError('rate limited', {
          status: 429,
          url: 'https://api.github.com/advisories',
          retryAfterMs: 123
        });
      }
      return { status: 200, value: 'ok' };
    }
  );

  assert.equal(result.retriesPerformed, 1);
  assert.deepEqual(delays, [123]);
});
