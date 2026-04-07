export class HttpRequestError extends Error {
  public readonly retryable: boolean;
  public readonly status: number | undefined;
  public readonly retryAfterMs: number | undefined;

  public constructor(message: string, retryable: boolean, status?: number, retryAfterMs?: number) {
    super(message);
    this.name = 'HttpRequestError';
    this.retryable = retryable;
    this.status = status;
    this.retryAfterMs = retryAfterMs;
  }
}
