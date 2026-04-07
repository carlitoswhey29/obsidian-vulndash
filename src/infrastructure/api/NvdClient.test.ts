import test from 'node:test';
import assert from 'node:assert/strict';
import { NvdClient } from './NvdClient';
import type { IHttpClient, HttpResponse } from '../../application/ports/IHttpClient';

test('reuses fixed since/until window across NVD pages and advances via API metadata', async () => {
  const seenUrls: string[] = [];
  const responses: Array<HttpResponse<unknown>> = [
    {
      status: 200,
      headers: {},
      data: {
        startIndex: 0,
        resultsPerPage: 2,
        totalResults: 4,
        vulnerabilities: [
          { cve: { id: 'CVE-1', published: '2026-01-01T00:00:00.000Z', lastModified: '2026-01-02T00:00:00.000Z' } },
          { cve: { id: 'CVE-1', published: '2026-01-01T00:00:00.000Z', lastModified: '2026-01-02T00:00:00.000Z' } }
        ]
      }
    },
    {
      status: 200,
      headers: {},
      data: {
        startIndex: 2,
        resultsPerPage: 2,
        totalResults: 4,
        vulnerabilities: [
          { cve: { id: 'CVE-2', published: '2026-01-03T00:00:00.000Z', lastModified: '2026-01-04T00:00:00.000Z' } }
        ]
      }
    }
  ];
  const httpClient: IHttpClient = {
    async getJson(url) {
      seenUrls.push(url);
      const next = responses.shift();
      if (!next) throw new Error('unexpected request');
      return next as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, '', { maxItems: 50, maxPages: 5 });
  const result = await client.fetchVulnerabilities({
    signal: new AbortController().signal,
    since: '2026-02-01T00:00:00.000Z',
    until: '2026-02-01T01:00:00.000Z'
  });

  assert.equal(result.pagesFetched, 2);
  assert.deepEqual(result.vulnerabilities.map((v) => v.id), ['CVE-1', 'CVE-2']);
  assert.match(seenUrls[0] ?? '', /lastModStartDate=2026-02-01T00%3A00%3A00.000Z/);
  assert.match(seenUrls[0] ?? '', /lastModEndDate=2026-02-01T01%3A00%3A00.000Z/);
  assert.match(seenUrls[1] ?? '', /lastModStartDate=2026-02-01T00%3A00%3A00.000Z/);
  assert.match(seenUrls[1] ?? '', /lastModEndDate=2026-02-01T01%3A00%3A00.000Z/);
  assert.match(seenUrls[0] ?? '', /startIndex=0/);
  assert.match(seenUrls[1] ?? '', /startIndex=2/);
});
