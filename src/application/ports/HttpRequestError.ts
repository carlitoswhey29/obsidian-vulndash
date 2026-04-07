export interface HttpErrorMetadata {
  status?: number;
  headers?: Record<string, string>;
  url: string;
  retryAfterMs?: number;
}

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

export class ServerHttpError extends HttpRequestError {
  public constructor(message: string, metadata: HttpErrorMetadata) {
    super('ServerHttpError', message, true, metadata);
  }
}
