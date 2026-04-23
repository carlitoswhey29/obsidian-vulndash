import test from 'node:test';
import assert from 'node:assert/strict';
import type { IHttpClient, HttpResponse } from '../../../src/application/ports/HttpClient';
import { buildFeedsFromConfig } from '../../../src/infrastructure/factories/FeedFactory';
import { OsvFeedClient } from '../../../src/infrastructure/clients/osv/OsvFeedClient';
import type { IOsvQueryCache } from '../../../src/infrastructure/clients/osv/IOsvQueryCache';
import type { FeedConfig } from '../../../src/application/use-cases/types';
import { BUILT_IN_FEEDS, FEED_TYPES } from '../../../src/domain/feeds/FeedTypes';
import type { PersistedComponentQueryRecord } from '../../../src/infrastructure/storage/VulnCacheSchema';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

const httpClient: IHttpClient = {
  async getJson<T>(): Promise<HttpResponse<T>> {
    throw new Error('not_implemented');
  }
};

const controls = {
  maxPages: 2,
  maxItems: 25,
  retryCount: 1,
  backoffBaseMs: 5,
  overlapWindowMs: 60_000,
  bootstrapLookbackMs: 3_600_000,
  debugHttpMetadata: false
};

test('builds only enabled feeds and skips invalid config entries', () => {
  const configs: FeedConfig[] = [
    { id: BUILT_IN_FEEDS.NVD.id, name: BUILT_IN_FEEDS.NVD.name, type: FEED_TYPES.NVD, enabled: true, apiKey: 'k' },
    { id: 'github-default', name: 'GitHub', type: FEED_TYPES.GITHUB_ADVISORY, enabled: false, token: 'x' },
    { id: 'repo-feed', name: 'Repo feed', type: FEED_TYPES.GITHUB_REPO, enabled: true, repoPath: 'Owner/Repo', token: 'x' },
    { id: 'generic-invalid', name: 'Custom', type: FEED_TYPES.GENERIC_JSON, enabled: true, url: '   ' },
    {
      id: BUILT_IN_FEEDS.OSV.id,
      name: BUILT_IN_FEEDS.OSV.name,
      type: FEED_TYPES.OSV,
      enabled: true,
      cacheTtlMs: 21_600_000,
      negativeCacheTtlMs: 3_600_000,
      requestTimeoutMs: 15_000,
      maxConcurrentBatches: 4
    }
  ];

  const feeds = buildFeedsFromConfig(configs, httpClient, controls);

  assert.equal(feeds.length, 2);
  assert.deepEqual(feeds.map((feed) => feed.id), [BUILT_IN_FEEDS.NVD.id, 'repo-feed']);
});

test('builds an OSV feed when runtime dependencies are provided', async () => {
  const configs: FeedConfig[] = [
    {
      id: BUILT_IN_FEEDS.OSV.id,
      name: BUILT_IN_FEEDS.OSV.name,
      type: FEED_TYPES.OSV,
      enabled: true,
      cacheTtlMs: 21_600_000,
      negativeCacheTtlMs: 3_600_000,
      requestTimeoutMs: 15_000,
      maxConcurrentBatches: 4
    }
  ];
  const seenPurls: string[][] = [];
  const savedRecords: PersistedComponentQueryRecord[][] = [];
  let getPurlsCalls = 0;
  let requestBody: unknown;

  const osvQueryCache: IOsvQueryCache = {
    async loadComponentQueries(): Promise<Map<string, PersistedComponentQueryRecord>> {
      return new Map();
    },
    async saveComponentQueries(records: readonly PersistedComponentQueryRecord[]): Promise<void> {
      savedRecords.push([...records]);
    },
    async markComponentQueriesSeen(purls: readonly string[]): Promise<void> {
      seenPurls.push([...purls]);
    },
    async pruneOrphanedComponentQueries(): Promise<number> {
      return 0;
    },
    async pruneExpiredComponentQueries(): Promise<number> {
      return 0;
    },
    async loadVulnerabilitiesByCacheKeys(): Promise<readonly Vulnerability[]> {
      return [];
    }
  };
  const osvHttpClient: IHttpClient = {
    ...httpClient,
    async postJson<TRequest, TResponse>(_url: string, body: TRequest): Promise<HttpResponse<TResponse>> {
      requestBody = body;
      return {
        data: {
          results: [{}]
        } as TResponse,
        headers: {},
        status: 200
      };
    }
  };

  const feeds = buildFeedsFromConfig(configs, osvHttpClient, controls, {
    getPurls: async () => {
      getPurlsCalls += 1;
      return ['pkg:npm/example@1.2.3'];
    },
    osvQueryCache
  });

  assert.equal(feeds.length, 1);
  assert.ok(feeds[0] instanceof OsvFeedClient);

  const result = await feeds[0]!.fetchVulnerabilities({
    signal: new AbortController().signal
  });

  assert.equal(getPurlsCalls, 1);
  assert.deepEqual(seenPurls, [['pkg:npm/example@1.2.3']]);
  assert.deepEqual(requestBody, {
    queries: [
      {
        package: {
          purl: 'pkg:npm/example@1.2.3'
        }
      }
    ]
  });
  assert.equal(result.vulnerabilities.length, 0);
  assert.equal(savedRecords.length, 1);
  assert.equal(savedRecords[0]?.[0]?.resultState, 'miss');
});

test('building an OSV feed does not affect existing feed construction', () => {
  const configs: FeedConfig[] = [
    { id: BUILT_IN_FEEDS.NVD.id, name: BUILT_IN_FEEDS.NVD.name, type: FEED_TYPES.NVD, enabled: true, apiKey: 'k' },
    { id: 'github-default', name: 'GitHub', type: FEED_TYPES.GITHUB_ADVISORY, enabled: true, token: 'x' },
    {
      id: BUILT_IN_FEEDS.OSV.id,
      name: BUILT_IN_FEEDS.OSV.name,
      type: FEED_TYPES.OSV,
      enabled: true,
      cacheTtlMs: 21_600_000,
      negativeCacheTtlMs: 3_600_000,
      requestTimeoutMs: 15_000,
      maxConcurrentBatches: 4
    }
  ];

  const feeds = buildFeedsFromConfig(configs, httpClient, controls, {
    getPurls: async () => ['pkg:npm/example@1.2.3'],
    osvQueryCache: {
      async loadComponentQueries(): Promise<Map<string, PersistedComponentQueryRecord>> {
        return new Map();
      },
      async saveComponentQueries(): Promise<void> {},
      async markComponentQueriesSeen(): Promise<void> {},
      async pruneOrphanedComponentQueries(): Promise<number> {
        return 0;
      },
      async pruneExpiredComponentQueries(): Promise<number> {
        return 0;
      },
      async loadVulnerabilitiesByCacheKeys(): Promise<readonly Vulnerability[]> {
        return [];
      }
    }
  });

  assert.deepEqual(feeds.map((feed) => feed.id), [BUILT_IN_FEEDS.NVD.id, 'github-default', BUILT_IN_FEEDS.OSV.id]);
});
