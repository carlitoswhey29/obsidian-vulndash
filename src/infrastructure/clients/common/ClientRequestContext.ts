export interface ClientRequestContext {
  providerName: string;
  operationName: string;
  url: string;
  safeHeaders: Record<string, string>;
  attemptNumber: number;
}
