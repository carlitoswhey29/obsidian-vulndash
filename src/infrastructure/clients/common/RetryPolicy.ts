export interface RetryPolicy {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  jitter: boolean;
}

export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 1_000,
  maxDelayMs: 30_000,
  jitter: true
};

export const normalizeRetryPolicy = (policy: Partial<RetryPolicy> = {}): RetryPolicy => ({
  maxAttempts: Math.max(1, Math.trunc(policy.maxAttempts ?? DEFAULT_RETRY_POLICY.maxAttempts)),
  baseDelayMs: Math.max(1, Math.trunc(policy.baseDelayMs ?? DEFAULT_RETRY_POLICY.baseDelayMs)),
  maxDelayMs: Math.max(1, Math.trunc(policy.maxDelayMs ?? DEFAULT_RETRY_POLICY.maxDelayMs)),
  jitter: policy.jitter ?? DEFAULT_RETRY_POLICY.jitter
});
