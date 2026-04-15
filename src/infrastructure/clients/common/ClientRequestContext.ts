export interface ClientRequestContext {
  provider: string;
  operation: string;
  url: string;
  headers: Record<string, string>;
  attempt: number;
  status?: number;
  retryDelayMs?: number;
  errorName?: string;
}
