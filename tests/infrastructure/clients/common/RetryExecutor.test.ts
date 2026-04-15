import test from 'node:test';
import assert from 'node:assert/strict';
import { ClientHttpError, RateLimitHttpError, RetryableNetworkError } from '../../../../src/application/ports/HttpRequestError';
import { NoopClientLogger } from '../../../../src/infrastructure/clients/common/ClientLogger';
import { RetryExecutor } from '../../../../src/infrastructure/clients/common/RetryExecutor';

test('retries retryable HttpRequestError failures until the request succeeds', async () => {
  const delays: number[] = [];
  let attempts = 0;
  const executor = new RetryExecutor(
    { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 100, jitter: false },
    new NoopClientLogger(),
    { sleep: async (delayMs: number) => { delays.push(delayMs); } }
  );

  const result = await executor.execute(
    async () => {
      attempts += 1;
      if (attempts < 3) {
        throw new RetryableNetworkError('temporary network issue', { url: 'https://example.test' });
      }
      return { status: 200, value: 'ok' };
    },
    {
      provider: 'NVD',
      operation: 'fetchVulnerabilities',
      url: 'https://example.test',
      headers: {}
    }
  );

  assert.equal(attempts, 3);
  assert.equal(result.status, 200);
  assert.deepEqual(delays, [10, 20]);
});

test('stops immediately on non-retryable HttpRequestError failures', async () => {
  const executor = new RetryExecutor(
    { maxAttempts: 3, baseDelayMs: 10, maxDelayMs: 100, jitter: false },
    new NoopClientLogger(),
    { sleep: async () => {} }
  );

  await assert.rejects(
    () => executor.execute(
      async () => {
        throw new ClientHttpError('bad request', { status: 400, url: 'https://example.test' });
      },
      {
        provider: 'NVD',
        operation: 'fetchVulnerabilities',
        url: 'https://example.test',
        headers: {}
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
    new NoopClientLogger(),
    { sleep: async (delayMs: number) => { delays.push(delayMs); } }
  );

  const result = await executor.execute(
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
    },
    {
      provider: 'GitHub',
      operation: 'fetchVulnerabilities',
      url: 'https://api.github.com/advisories',
      headers: {}
    }
  );

  assert.equal(result.status, 200);
  assert.deepEqual(delays, [123]);
});
