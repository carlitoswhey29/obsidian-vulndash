import type { ClientRequestContext } from './ClientRequestContext';

export interface ClientFailureLog {
  errorName: string;
  message: string;
  status?: number;
}

export interface ClientRetryLog extends ClientFailureLog {
  delayMs: number;
}

export interface ClientLogger {
  requestStart(context: ClientRequestContext): void;
  requestSuccess(context: ClientRequestContext, status: number): void;
  requestFailure(context: ClientRequestContext, failure: ClientFailureLog): void;
  requestRetry(context: ClientRequestContext, retry: ClientRetryLog): void;
}

export const consoleClientLogger: ClientLogger = {
  requestStart(context) {
    console.info('[vulndash.client.request.start]', context);
  },
  requestSuccess(context, status) {
    console.info('[vulndash.client.request.success]', {
      ...context,
      status
    });
  },
  requestFailure(context, failure) {
    console.warn('[vulndash.client.request.failure]', {
      ...context,
      ...failure
    });
  },
  requestRetry(context, retry) {
    console.info('[vulndash.client.request.retry]', {
      ...context,
      ...retry
    });
  }
};
