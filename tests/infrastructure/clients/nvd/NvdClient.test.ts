import test from 'node:test';
import assert from 'node:assert/strict';
import { NvdClient } from '../../../../src/infrastructure/clients/nvd/NvdClient';
import type { IHttpClient, HttpResponse } from '../../../../src/application/ports/IHttpClient';
import { AuthFailureHttpError, ClientHttpError, ServerHttpError } from '../../../../src/application/ports/HttpRequestError';
import type { ClientLogger } from '../../../../src/infrastructure/clients/common/ClientLogger';

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

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 50, maxPages: 5 });
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

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 10, maxPages: 2 });
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

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 10, maxPages: 2 });
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

test('uses the NVD English description as a descriptive title', async () => {
  const response: HttpResponse<unknown> = {
    status: 200,
    headers: {},
    data: {
      startIndex: 0,
      resultsPerPage: 1,
      totalResults: 1,
      vulnerabilities: [{
        cve: {
          id: 'CVE-2026-4000',
          published: '2026-02-01T00:00:00.000Z',
          lastModified: '2026-02-01T01:00:00.000Z',
          descriptions: [{
            lang: 'en',
            value: 'Remote attackers can trigger command injection via crafted input in the management API. Additional detail follows here.'
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

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 10, maxPages: 2 });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(
    result.vulnerabilities[0]?.title,
    'Remote attackers can trigger command injection via crafted input in the management API.'
  );
});

test('passes apiKey in NVD request headers instead of the query string', async () => {
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

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', 'secret-key', { maxItems: 10, maxPages: 2 });
  await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.doesNotMatch(seenUrl, /apiKey=secret-key/);
  assert.deepEqual(seenHeaders, { apiKey: 'secret-key' });
});

test('guards against duplicate NVD start indexes', async () => {
  const responses: Array<HttpResponse<unknown>> = [{
    status: 200,
    headers: {},
    data: {
      startIndex: 0,
      resultsPerPage: 0,
      totalResults: 2,
      vulnerabilities: [{
        cve: {
          id: 'CVE-2026-5000',
          published: '2026-02-01T00:00:00.000Z',
          lastModified: '2026-02-01T01:00:00.000Z'
        }
      }]
    }
  }];

  const httpClient: IHttpClient = {
    async getJson() {
      const next = responses.shift();
      if (!next) {
        throw new Error('unexpected request');
      }
      return next as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 10, maxPages: 5 });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(result.pagesFetched, 1);
  assert.ok(result.warnings.includes('duplicate_start_index'));
});

test('warns when NVD pagination hits the max pages guard', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: {
          startIndex: 0,
          resultsPerPage: 1,
          totalResults: 3,
          vulnerabilities: [{
            cve: {
              id: 'CVE-2026-5001',
              published: '2026-02-01T00:00:00.000Z',
              lastModified: '2026-02-01T01:00:00.000Z'
            }
          }]
        }
      } as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 10, maxPages: 1 });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.ok(result.warnings.includes('max_pages_reached'));
});

test('warns when NVD page results exceed the max items guard', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: {
          startIndex: 0,
          resultsPerPage: 2,
          totalResults: 2,
          vulnerabilities: [
            {
              cve: {
                id: 'CVE-2026-5002',
                published: '2026-02-01T00:00:00.000Z',
                lastModified: '2026-02-01T01:00:00.000Z'
              }
            },
            {
              cve: {
                id: 'CVE-2026-5003',
                published: '2026-02-01T00:00:00.000Z',
                lastModified: '2026-02-01T01:00:00.000Z'
              }
            }
          ]
        }
      } as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 1, maxPages: 2 });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(result.vulnerabilities.length, 1);
  assert.ok(result.warnings.includes('max_items_reached'));
});

test('validateConnection surfaces provider-specific NVD auth guidance', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      throw new ClientHttpError('HTTP 403', { status: 403, url: 'https://services.nvd.nist.gov/rest/json/cves/2.0' });
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', { maxItems: 10, maxPages: 2 });
  await assert.rejects(
    () => client.validateConnection(new AbortController().signal),
    (error: unknown) => error instanceof AuthFailureHttpError && error.message.includes('Configure a valid NVD API key')
  );
});

test('tracks retriesPerformed from the shared retry executor for NVD requests', async () => {
  let attempts = 0;
  const httpClient: IHttpClient = {
    async getJson() {
      attempts += 1;
      if (attempts === 1) {
        throw new ServerHttpError('HTTP 503', {
          status: 503,
          url: 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        });
      }

      return {
        status: 200,
        headers: {},
        data: {
          startIndex: 0,
          resultsPerPage: 1,
          totalResults: 1,
          vulnerabilities: [{
            cve: {
              id: 'CVE-2026-6000',
              published: '2026-02-01T00:00:00.000Z',
              lastModified: '2026-02-01T01:00:00.000Z'
            }
          }]
        }
      } as HttpResponse<never>;
    }
  };

  const client = new NvdClient(httpClient, 'nvd-default', 'NVD', '', {
    maxItems: 10,
    maxPages: 2,
    retryCount: 1,
    backoffBaseMs: 1
  });
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(attempts, 2);
  assert.equal(result.retriesPerformed, 1);
  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['CVE-2026-6000']);
});

test('sanitizes NVD apiKey headers before request logging', async () => {
  const seenHeaders: Array<Record<string, string>> = [];
  const logger: ClientLogger = {
    onRequestStart(context) {
      seenHeaders.push(context.headers);
    },
    onRequestSuccess() {},
    onRequestRetry() {},
    onRequestFailure() {}
  };
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: {
          startIndex: 0,
          resultsPerPage: 1,
          totalResults: 1,
          vulnerabilities: [{
            cve: {
              id: 'CVE-2026-7000',
              published: '2026-02-01T00:00:00.000Z',
              lastModified: '2026-02-01T01:00:00.000Z'
            }
          }]
        }
      } as HttpResponse<never>;
    }
  };

  const client = new NvdClient(
    httpClient,
    'nvd-default',
    'NVD',
    'secret-key',
    { maxItems: 10, maxPages: 2 },
    { logger }
  );
  await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(seenHeaders.length, 1);
  assert.deepEqual(seenHeaders[0], { apiKey: '[REDACTED]' });
});
