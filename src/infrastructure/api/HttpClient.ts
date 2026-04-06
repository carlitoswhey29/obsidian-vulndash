export class HttpClient {
  public async getJson<T>(url: string, headers: Record<string, string>, signal: AbortSignal): Promise<T> {
    const response = await fetch(url, { method: 'GET', headers, signal });
    if (response.status === 429) {
      throw new Error('rate_limit');
    }
    if (!response.ok) {
      throw new Error(`http_${response.status}`);
    }
    return (await response.json()) as T;
  }
}
