export interface RetryPolicy {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  jitter: boolean;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 1,
  baseDelayMs: 1_000,
  maxDelayMs: 30_000,
  jitter: true
};

export const normalizeRetryPolicy = (policy: Partial<RetryPolicy>): RetryPolicy => ({
  maxAttempts: Math.max(1, Math.trunc(policy.maxAttempts ?? DEFAULT_RETRY_POLICY.maxAttempts)),
  baseDelayMs: Math.max(1, Math.trunc(policy.baseDelayMs ?? DEFAULT_RETRY_POLICY.baseDelayMs)),
  maxDelayMs: Math.max(1, Math.trunc(policy.maxDelayMs ?? DEFAULT_RETRY_POLICY.maxDelayMs)),
  jitter: policy.jitter ?? DEFAULT_RETRY_POLICY.jitter
});

export const computeRetryDelayMs = (
  policy: RetryPolicy,
  attemptNumber: number,
  retryAfterMs: number | undefined,
  random: () => number = Math.random
): number => {
  if (retryAfterMs !== undefined) {
    return Math.max(0, retryAfterMs);
  }

  const exponent = Math.max(0, attemptNumber - 1);
  const bounded = Math.min(policy.baseDelayMs * (2 ** exponent), policy.maxDelayMs);
  if (!policy.jitter) {
    return bounded;
  }

  const jitterMultiplier = 0.5 + random();
  return Math.min(policy.maxDelayMs, Math.max(0, Math.round(bounded * jitterMultiplier)));
};
