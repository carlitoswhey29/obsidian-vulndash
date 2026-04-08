import test from 'node:test';
import assert from 'node:assert/strict';
import { NvdClient } from '../../../src/infrastructure/api/NvdClient';
import type { IHttpClient, HttpResponse } from '../../../src/application/ports/IHttpClient';

const secretProvider = (secret: string) => async (): Promise<string> => secret;

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

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', secretProvider(''), { maxItems: 50, maxPages: 5 });
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

test('normalizes CPE affected products into readable names', async () => {
  const response: HttpResponse<unknown> = {
    status: 200,
    headers: {},
    data: {
      startIndex: 0,
      resultsPerPage: 1,
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: 'CVE-2026-1000',
          published: '2026-02-01T00:00:00.000Z',
          lastModified: '2026-02-01T01:00:00.000Z',
          configurations: [{
            nodes: [{
              cpeMatch: [
                { criteria: 'cpe:2.3:a:apache:tomcat:10.1.31:*:*:*:*:*:*:*' },
                { criteria: 'cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*' }
              ]
            }]
          }]
        }
      }]
    }
  };

  const httpClient: IHttpClient = {
    async getJson() {
      return response as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', secretProvider(''), { maxItems: 10, maxPages: 2 });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(result.vulnerabilities[0]?.affectedProducts, ['Apache Tomcat 10.1.31', 'Nodejs Node.js']);
});

test('normalizes NVD CWE vendor product and version metadata', async () => {
  const response: HttpResponse<unknown> = {
    status: 200,
    headers: {},
    data: {
      startIndex: 0,
      resultsPerPage: 1,
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: 'CVE-2026-3000',
          published: '2026-02-01T00:00:00.000Z',
          lastModified: '2026-02-01T01:00:00.000Z',
          weaknesses: [{
            description: [
              { lang: 'en', value: 'CWE-79' },
              { lang: 'en', value: 'NVD-CWE-noinfo' }
            ]
          }],
          references: [{ url: 'https://vendor.example.com/CVE-2026-3000' }],
          metrics: {
            cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }]
          },
          configurations: [{
            nodes: [{
              cpeMatch: [{
                vulnerable: true,
                criteria: 'cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*',
                versionStartIncluding: '1.0.0',
                versionEndExcluding: '2.0.0'
              }]
            }]
          }]
        }
      }]
    }
  };

  const httpClient: IHttpClient = {
    async getJson() {
      return response as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', secretProvider(''), { maxItems: 10, maxPages: 2 });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });
  const vulnerability = result.vulnerabilities[0];

  assert.equal(vulnerability?.metadata?.cveId, 'CVE-2026-3000');
  assert.deepEqual(vulnerability?.metadata?.cwes, ['CWE-79']);
  assert.deepEqual(vulnerability?.metadata?.vendors, ['Microsoft']);
  assert.deepEqual(vulnerability?.metadata?.packages, ['Edge']);
  assert.deepEqual(vulnerability?.metadata?.vulnerableVersionRanges, ['Microsoft Edge: >= 1.0.0, < 2.0.0']);
  assert.equal(vulnerability?.metadata?.affectedPackages?.[0]?.vendor, 'Microsoft');
  assert.equal(vulnerability?.metadata?.affectedPackages?.[0]?.name, 'Edge');
  assert.equal(vulnerability?.metadata?.sourceUrls?.html, 'https://nvd.nist.gov/vuln/detail/CVE-2026-3000');
  assert.ok(vulnerability?.references.includes('https://vendor.example.com/CVE-2026-3000'));
});

test('passes apiKey in the NVD query string instead of request headers', async () => {
  let seenUrl = '';
  let seenHeaders: Record<string, string> | undefined;

  const response: HttpResponse<unknown> = {
    status: 200,
    headers: {},
    data: {
      startIndex: 0,
      resultsPerPage: 1,
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: 'CVE-2026-2000',
          published: '2026-02-01T00:00:00.000Z',
          lastModified: '2026-02-01T01:00:00.000Z'
        }
      }]
    }
  };

  const httpClient: IHttpClient = {
    async getJson(url, headers) {
      seenUrl = url;
      seenHeaders = headers;
      return response as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', secretProvider('secret-key'), { maxItems: 10, maxPages: 2 });
  await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.match(seenUrl, /apiKey=secret-key/);
  assert.deepEqual(seenHeaders, {});
});

test('NVD auth validation failure does not leak API key', async () => {
  const secret = 'nvd-secret-key';
  const httpClient: IHttpClient = {
    async getJson() {
      throw new Error('NVD request forbidden (403). API key may be missing required permissions.');
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', secretProvider(secret), { maxItems: 10, maxPages: 2 });
  const result = await client.validateConnection(new AbortController().signal);

  assert.equal(result.ok, false);
  assert.equal(result.message.includes(secret), false);
});
