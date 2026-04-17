export interface HttpResponse<T> {
  data: T;
  status: number;
  headers: Record<string, string>;
}

export interface IHttpClient {
  getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<HttpResponse<T>>;
}
