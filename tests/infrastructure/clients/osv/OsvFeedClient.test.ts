import assert from 'node:assert/strict';
import test from 'node:test';
import type { HttpResponse, IHttpClient } from '../../../../src/application/ports/HttpClient';
import type { Vulnerability } from '../../../../src/domain/entities/Vulnerability';
import { RetryableNetworkError, ServerHttpError } from '../../../../src/application/ports/DataSourceError';
import type { OsvFeedConfig } from '../../../../src/application/use-cases/types';
import { OsvFeedClient } from '../../../../src/infrastructure/clients/osv/OsvFeedClient';
import { buildOsvVulnerabilityCacheKey } from '../../../../src/infrastructure/clients/osv/OsvCacheKey';
import type { IOsvQueryCache } from '../../../../src/infrastructure/clients/osv/IOsvQueryCache';
import type {
  OsvBatchRequest,
  OsvBatchResponse,
  OsvVulnerabilityPayload
} from '../../../../src/infrastructure/clients/osv/OsvTypes';
import type { PersistedComponentQueryRecord } from '../../../../src/infrastructure/storage/VulnCacheSchema';

class FakeOsvQueryCache implements IOsvQueryCache {
  public readonly loadedPurls: Array<readonly string[]> = [];
  public readonly markSeenCalls: Array<{ purls: readonly string[]; seenAtMs: number }> = [];
  public readonly orphanPrunes: ReadonlySet<string>[] = [];
  public readonly expiryPrunes: number[] = [];
  public readonly savedRecords: PersistedComponentQueryRecord[] = [];
  public readonly loadedKeys: Array<readonly string[]> = [];
  private readonly componentQueries = new Map<string, PersistedComponentQueryRecord>();
  private readonly vulnerabilitiesByKey = new Map<string, Vulnerability>();

  public setComponentQueries(records: readonly PersistedComponentQueryRecord[]): void {
    for (const record of records) {
      this.componentQueries.set(record.purl, record);
    }
  }

  public setVulnerabilities(entries: Readonly<Record<string, Vulnerability>>): void {
    for (const [key, vulnerability] of Object.entries(entries)) {
      this.vulnerabilitiesByKey.set(key, vulnerability);
    }
  }

  public async loadComponentQueries(purls: readonly string[]): Promise<Map<string, PersistedComponentQueryRecord>> {
    this.loadedPurls.push([...purls]);
    return new Map(purls
      .map((purl) => [purl, this.componentQueries.get(purl)] as const)
      .filter((entry): entry is readonly [string, PersistedComponentQueryRecord] => Boolean(entry[1])));
  }

  public async saveComponentQueries(records: readonly PersistedComponentQueryRecord[]): Promise<void> {
    this.savedRecords.push(...records);
    for (const record of records) {
      this.componentQueries.set(record.purl, record);
    }
  }

  public async markComponentQueriesSeen(purls: readonly string[], seenAtMs: number): Promise<void> {
    this.markSeenCalls.push({ purls: [...purls], seenAtMs });
  }

  public async pruneOrphanedComponentQueries(activePurls: ReadonlySet<string>): Promise<number> {
    this.orphanPrunes.push(activePurls);
    return 0;
  }

  public async pruneExpiredComponentQueries(cutoffMs: number): Promise<number> {
    this.expiryPrunes.push(cutoffMs);
    return 0;
  }

  public async loadVulnerabilitiesByCacheKeys(keys: readonly string[]): Promise<readonly Vulnerability[]> {
    this.loadedKeys.push([...keys]);
    return keys
      .map((key) => this.vulnerabilitiesByKey.get(key))
      .filter((vulnerability): vulnerability is Vulnerability => Boolean(vulnerability));
  }
}

class FakeHttpClient implements IHttpClient {
  public readonly postBodies: OsvBatchRequest[] = [];
  public readonly postUrls: string[] = [];
  private readonly handlers: Array<(body: OsvBatchRequest) => Promise<HttpResponse<OsvBatchResponse>>>;

  public constructor(handlers: Array<(body: OsvBatchRequest) => Promise<HttpResponse<OsvBatchResponse>>>) {
    this.handlers = [...handlers];
  }

  public async getJson<T>(): Promise<HttpResponse<T>> {
    throw new Error('unexpected GET request');
  }

  public async postJson<TRequest, TResponse>(
    url: string,
    body: TRequest,
    _headers: Record<string, string>,
    _signal: AbortSignal
  ): Promise<HttpResponse<TResponse>> {
    const typedBody = body as unknown as OsvBatchRequest;
    this.postUrls.push(url);
    this.postBodies.push(typedBody);
    const next = this.handlers.shift();
    if (!next) {
      throw new Error('unexpected POST request');
    }

    return next(typedBody) as Promise<HttpResponse<TResponse>>;
  }
}

const createConfig = (overrides: Partial<OsvFeedConfig> = {}): OsvFeedConfig => ({
  id: 'osv-default',
  name: 'OSV',
  type: 'osv',
  enabled: true,
  cacheTtlMs: 60_000,
  negativeCacheTtlMs: 30_000,
  requestTimeoutMs: 15_000,
  maxConcurrentBatches: 2,
  osvEndpointUrl: 'https://api.osv.dev/v1/querybatch',
  osvMaxBatchSize: 1000,
  ...overrides
});

const createControls = () => ({
  maxItems: 500,
  maxPages: 10,
  retryCount: 0,
  backoffBaseMs: 1
});

const createVulnerabilityPayload = (
  id: string,
  overrides: Partial<OsvVulnerabilityPayload> = {}
): OsvVulnerabilityPayload => ({
  id,
  modified: '2026-04-22T00:00:00.000Z',
  published: '2026-04-21T00:00:00.000Z',
  summary: `${id} summary`,
  details: `${id} details`,
  severity: [{ type: 'CVSS_V3', score: '7.5' }],
  affected: [{
    package: {
      ecosystem: 'npm',
      name: '@example/widget',
      purl: 'pkg:npm/@example/widget@1.2.3'
    }
  }],
  ...overrides
});

const createDomainVulnerability = (id: string, source = 'OSV'): Vulnerability => ({
  affectedProducts: ['@example/widget'],
  cvssScore: 7.5,
  id,
  publishedAt: '2026-04-21T00:00:00.000Z',
  references: [`https://osv.dev/vulnerability/${id}`],
  severity: 'HIGH',
  source,
  summary: `${id} details`,
  title: `${id} summary`,
  updatedAt: '2026-04-22T00:00:00.000Z'
});

const createQueryRecord = (
  purl: string,
  overrides: Partial<PersistedComponentQueryRecord> = {}
): PersistedComponentQueryRecord => ({
  purl,
  source: 'osv',
  lastQueriedAtMs: Date.now(),
  lastSeenInWorkspaceAtMs: Date.now(),
  resultState: 'hit',
  vulnerabilityCacheKeys: [],
  ...overrides
});

const createClient = (
  httpClient: IHttpClient,
  queryCache: IOsvQueryCache,
  getPurls: () => Promise<readonly string[]>,
  configOverrides: Partial<OsvFeedConfig> = {}
): OsvFeedClient =>
  new OsvFeedClient(
    httpClient,
    queryCache,
    getPurls,
    createControls(),
    createConfig(configOverrides)
  );

test('blank, invalid, and unresolved PURLs are ignored', async () => {
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async (body) => ({
      status: 200,
      headers: {},
      data: {
        results: body.queries.map(() => ({ vulns: [] }))
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => [
    '',
    'not-a-purl',
    'pkg:npm/react',
    ' PKG:NPM/%40EXAMPLE/WIDGET@1.2.3 '
  ]);

  await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(queryCache.loadedPurls[0], ['pkg:npm/@example/widget@1.2.3']);
  assert.deepEqual(queryCache.markSeenCalls[0]?.purls, ['pkg:npm/@example/widget@1.2.3']);
  assert.equal(httpClient.postBodies[0]?.queries.length, 1);
});

test('positive cache TTL is honored', async () => {
  const queryCache = new FakeOsvQueryCache();
  const nowMs = Date.now();
  const activePurl = 'pkg:npm/@example/widget@1.2.3';
  const cacheKey = buildOsvVulnerabilityCacheKey('OSV-2026-1', 'osv-default');
  queryCache.setComponentQueries([
    createQueryRecord(activePurl, {
      lastQueriedAtMs: nowMs - 10_000,
      resultState: 'hit',
      vulnerabilityCacheKeys: [cacheKey]
    })
  ]);
  queryCache.setVulnerabilities({
    [cacheKey]: createDomainVulnerability('OSV-2026-1')
  });
  const httpClient = new FakeHttpClient([]);
  const client = createClient(httpClient, queryCache, async () => [activePurl]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(httpClient.postBodies.length, 0);
  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-1']);
});

test('cached positive results are rehydrated', async () => {
  const queryCache = new FakeOsvQueryCache();
  const activePurl = 'pkg:npm/@example/widget@1.2.3';
  const cacheKey = buildOsvVulnerabilityCacheKey('OSV-2026-2', 'osv-default');
  queryCache.setComponentQueries([
    createQueryRecord(activePurl, {
      lastQueriedAtMs: Date.now(),
      resultState: 'hit',
      vulnerabilityCacheKeys: [cacheKey]
    })
  ]);
  queryCache.setVulnerabilities({
    [cacheKey]: createDomainVulnerability('OSV-2026-2')
  });
  const httpClient = new FakeHttpClient([]);
  const client = createClient(httpClient, queryCache, async () => [activePurl]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(queryCache.loadedKeys[0], [cacheKey]);
  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-2']);
});

test('negative cache TTL is honored', async () => {
  const queryCache = new FakeOsvQueryCache();
  const activePurl = 'pkg:npm/@example/widget@1.2.3';
  queryCache.setComponentQueries([
    createQueryRecord(activePurl, {
      lastQueriedAtMs: Date.now() - 5_000,
      resultState: 'miss'
    })
  ]);
  const httpClient = new FakeHttpClient([]);
  const client = createClient(httpClient, queryCache, async () => [activePurl]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(httpClient.postBodies.length, 0);
  assert.deepEqual(result.vulnerabilities, []);
});

test('error-state query records do not suppress re-querying', async () => {
  const queryCache = new FakeOsvQueryCache();
  const activePurl = 'pkg:npm/@example/widget@1.2.3';
  queryCache.setComponentQueries([
    createQueryRecord(activePurl, {
      lastQueriedAtMs: Date.now(),
      resultState: 'error'
    })
  ]);
  const httpClient = new FakeHttpClient([
    async (body) => ({
      status: 200,
      headers: {},
      data: {
        results: body.queries.map(() => ({ vulns: [createVulnerabilityPayload('OSV-2026-3')] }))
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => [activePurl]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(httpClient.postBodies.length, 1);
  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-3']);
});

test('configured batch size chunks requests using the runtime config', async () => {
  const purls = Array.from({ length: 5 }, (_, index) => `pkg:npm/example-${index}@1.0.0`);
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async (body) => ({
      status: 200,
      headers: {},
      data: { results: body.queries.map(() => ({ vulns: [] })) }
    }),
    async (body) => ({
      status: 200,
      headers: {},
      data: { results: body.queries.map(() => ({ vulns: [] })) }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => purls, { osvMaxBatchSize: 2 });

  await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(httpClient.postBodies.length, 3);
  assert.equal(httpClient.postBodies[0]?.queries.length, 2);
  assert.equal(httpClient.postBodies[1]?.queries.length, 2);
  assert.equal(httpClient.postBodies[2]?.queries.length, 1);
});

test('configured endpoint URL is used for batch requests', async () => {
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async () => ({
      status: 200,
      headers: {},
      data: {
        results: [{ vulns: [] }]
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => ['pkg:npm/a@1.0.0'], {
    osvEndpointUrl: 'https://osv.internal.example/v1/querybatch'
  });

  await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(httpClient.postUrls, ['https://osv.internal.example/v1/querybatch']);
});

test('duplicate vulnerabilities across multiple PURLs are deduped', async () => {
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async () => ({
      status: 200,
      headers: {},
      data: {
        results: [
          { vulns: [createVulnerabilityPayload('OSV-2026-4')] },
          { vulns: [createVulnerabilityPayload('OSV-2026-4')] }
        ]
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => [
    'pkg:npm/a@1.0.0',
    'pkg:npm/b@1.0.0'
  ]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-4']);
});

test('failed requests do not create false miss records', async () => {
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async () => {
      throw new ServerHttpError('boom', { url: 'https://api.osv.dev/v1/querybatch' });
    }
  ]);
  const client = createClient(httpClient, queryCache, async () => ['pkg:npm/a@1.0.0']);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(queryCache.savedRecords.length, 1);
  assert.equal(queryCache.savedRecords[0]?.resultState, 'error');
  assert.equal(queryCache.savedRecords[0]?.vulnerabilityCacheKeys.length, 0);
  assert.deepEqual(result.vulnerabilities, []);
  assert.deepEqual(result.warnings, ['partial_failure']);
});

test('truncated batch responses are treated as partial failures instead of clean misses', async () => {
  const queryCache = new FakeOsvQueryCache();
  const activePurl = 'pkg:npm/a@1.0.0';
  const httpClient = new FakeHttpClient([
    async () => ({
      status: 200,
      headers: {},
      data: {
        results: []
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => [activePurl]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(result.vulnerabilities, []);
  assert.deepEqual(result.warnings, ['partial_failure']);
  assert.equal(queryCache.savedRecords[0]?.purl, activePurl);
  assert.equal(queryCache.savedRecords[0]?.resultState, 'error');
});

test('partial failure preserves successful results', async () => {
  const queryCache = new FakeOsvQueryCache();
  const cachedFallbackKey = buildOsvVulnerabilityCacheKey('OSV-2026-10', 'osv-default');
  queryCache.setComponentQueries([
    createQueryRecord('pkg:npm/a@1.0.0', {
      lastQueriedAtMs: 0,
      lastSeenInWorkspaceAtMs: 0,
      resultState: 'hit',
      vulnerabilityCacheKeys: [cachedFallbackKey]
    })
  ]);
  queryCache.setVulnerabilities({
    [cachedFallbackKey]: createDomainVulnerability('OSV-2026-10')
  });
  const httpClient = new FakeHttpClient([
    async () => ({
      status: 200,
      headers: {},
      data: {
        results: [
          {
            vulns: [createVulnerabilityPayload('OSV-2026-11')],
            next_page_token: 'token-a'
          },
          {
            vulns: [createVulnerabilityPayload('OSV-2026-12')]
          }
        ]
      }
    }),
    async () => {
      throw new RetryableNetworkError('boom', { url: 'https://api.osv.dev/v1/querybatch' });
    }
  ]);
  const client = createClient(httpClient, queryCache, async () => [
    'pkg:npm/a@1.0.0',
    'pkg:npm/b@1.0.0'
  ]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-10', 'OSV-2026-12']);
  assert.deepEqual(result.warnings, ['partial_failure']);
  assert.equal(queryCache.savedRecords.some((record) => record.purl === 'pkg:npm/b@1.0.0' && record.resultState === 'hit'), true);
  assert.equal(queryCache.savedRecords.some((record) => record.purl === 'pkg:npm/a@1.0.0' && record.resultState === 'error'), true);
});

test('observability changes do not change functional behavior', async () => {
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async () => ({
      status: 200,
      headers: {},
      data: {
        results: [
          {
            vulns: [createVulnerabilityPayload('OSV-2026-13')]
          }
        ]
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => ['pkg:npm/a@1.0.0']);
  const originalInfo = console.info;
  const originalWarn = console.warn;
  const infoCalls: unknown[][] = [];
  const warnCalls: unknown[][] = [];

  console.info = (...args: unknown[]): void => {
    infoCalls.push(args);
  };
  console.warn = (...args: unknown[]): void => {
    warnCalls.push(args);
  };

  try {
    const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

    assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-13']);
    assert.equal(result.warnings.length, 0);
    assert.equal(infoCalls.length >= 2, true);
    assert.equal(warnCalls.length, 0);
  } finally {
    console.info = originalInfo;
    console.warn = originalWarn;
  }
});

test('per-query pagination is handled correctly', async () => {
  const queryCache = new FakeOsvQueryCache();
  const httpClient = new FakeHttpClient([
    async (body) => ({
      status: 200,
      headers: {},
      data: {
        results: body.queries.map((query) => query.package?.purl === 'pkg:npm/a@1.0.0'
          ? {
              vulns: [createVulnerabilityPayload('OSV-2026-5')],
              next_page_token: 'token-a'
            }
          : {
              vulns: [createVulnerabilityPayload('OSV-2026-6')]
            })
      }
    }),
    async () => ({
      status: 200,
      headers: {},
      data: {
        results: [
          {
            vulns: [createVulnerabilityPayload('OSV-2026-7')]
          }
        ]
      }
    })
  ]);
  const client = createClient(httpClient, queryCache, async () => [
    'pkg:npm/a@1.0.0',
    'pkg:npm/b@1.0.0'
  ]);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(httpClient.postBodies.length, 2);
  assert.equal(httpClient.postBodies[1]?.queries[0]?.page_token, 'token-a');
  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-5', 'OSV-2026-6', 'OSV-2026-7']);
});

test('inactive cached positives are excluded from the returned snapshot', async () => {
  const queryCache = new FakeOsvQueryCache();
  const activeKey = buildOsvVulnerabilityCacheKey('OSV-2026-8', 'osv-default');
  const inactiveKey = buildOsvVulnerabilityCacheKey('OSV-2026-9', 'osv-default');
  queryCache.setComponentQueries([
    createQueryRecord('pkg:npm/active@1.0.0', {
      lastQueriedAtMs: Date.now(),
      resultState: 'hit',
      vulnerabilityCacheKeys: [activeKey]
    }),
    createQueryRecord('pkg:npm/inactive@1.0.0', {
      lastQueriedAtMs: Date.now(),
      resultState: 'hit',
      vulnerabilityCacheKeys: [inactiveKey]
    })
  ]);
  queryCache.setVulnerabilities({
    [activeKey]: createDomainVulnerability('OSV-2026-8'),
    [inactiveKey]: createDomainVulnerability('OSV-2026-9')
  });
  const httpClient = new FakeHttpClient([]);
  const client = createClient(httpClient, queryCache, async () => ['pkg:npm/active@1.0.0']);

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.deepEqual(result.vulnerabilities.map((vulnerability) => vulnerability.id), ['OSV-2026-8']);
  assert.equal(queryCache.orphanPrunes[0]?.has('pkg:npm/active@1.0.0'), true);
  assert.equal(queryCache.orphanPrunes[0]?.has('pkg:npm/inactive@1.0.0'), false);
});
