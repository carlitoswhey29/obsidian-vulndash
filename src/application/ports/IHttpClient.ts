export interface IHttpClient {
  getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<T>;
}

