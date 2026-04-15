import type { ClientRequestContext } from './ClientRequestContext';

export interface ClientLogger {
  onRequestStart(context: ClientRequestContext): void;
  onRequestSuccess(context: ClientRequestContext): void;
  onRequestRetry(context: ClientRequestContext): void;
  onRequestFailure(context: ClientRequestContext): void;
}

export class NoopClientLogger implements ClientLogger {
  public onRequestStart(_context: ClientRequestContext): void {
    // Intentionally empty.
  }

  public onRequestSuccess(_context: ClientRequestContext): void {
    // Intentionally empty.
  }

  public onRequestRetry(_context: ClientRequestContext): void {
    // Intentionally empty.
  }

  public onRequestFailure(_context: ClientRequestContext): void {
    // Intentionally empty.
  }
}
