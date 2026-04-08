export interface HttpErrorMetadata {
  status?: number;
  headers?: Record<string, string>;
  url: string;
  retryAfterMs?: number;
  authFailureReason?: AuthFailureReason;
}

export type AuthFailureReason = 'unauthorized' | 'forbidden';

export abstract class HttpRequestError extends Error {
  public readonly retryable: boolean;
  public readonly metadata: HttpErrorMetadata;

  protected constructor(name: string, message: string, retryable: boolean, metadata: HttpErrorMetadata) {
    super(message);
    this.name = name;
    this.retryable = retryable;
    this.metadata = metadata;
  }
}

export class RetryableNetworkError extends HttpRequestError {
  public constructor(message: string, metadata: HttpErrorMetadata) {
    super('RetryableNetworkError', message, true, metadata);
  }
}

export class TimeoutHttpError extends HttpRequestError {
  public constructor(message: string, metadata: HttpErrorMetadata) {
    super('TimeoutHttpError', message, true, metadata);
  }
}

export class RateLimitHttpError extends HttpRequestError {
  public constructor(message: string, metadata: HttpErrorMetadata) {
    super('RateLimitHttpError', message, true, metadata);
  }
}

export class ClientHttpError extends HttpRequestError {
  public constructor(message: string, metadata: HttpErrorMetadata) {
    super('ClientHttpError', message, false, metadata);
  }
}

export class AuthFailureHttpError extends ClientHttpError {
  public readonly authFailureReason: AuthFailureReason;

  public constructor(message: string, metadata: HttpErrorMetadata, reason: AuthFailureReason) {
    super(message, { ...metadata, authFailureReason: reason });
    this.name = 'AuthFailureHttpError';
    this.authFailureReason = reason;
  }
}

export class ServerHttpError extends HttpRequestError {
  public constructor(message: string, metadata: HttpErrorMetadata) {
    super('ServerHttpError', message, true, metadata);
  }
}
