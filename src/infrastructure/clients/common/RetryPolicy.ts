export interface RetryDecision {
  retry: boolean;
  delayMs: number;
}

export function computeRetryDecision(
  attempt: number,
  maxAttempts: number,
  retryAfterSeconds?: number
): RetryDecision {
  if (attempt >= maxAttempts) {
    return { retry: false, delayMs: 0 };
  }

  if (retryAfterSeconds && retryAfterSeconds > 0) {
    return { retry: true, delayMs: retryAfterSeconds * 1000 };
  }

  const delayMs = Math.min(1000 * 2 ** attempt, 10000);
  return { retry: true, delayMs };
}
