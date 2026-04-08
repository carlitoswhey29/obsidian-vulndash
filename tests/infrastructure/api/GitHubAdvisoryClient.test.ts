import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubAdvisoryClient, extractNextLink } from '../../../src/infrastructure/api/GitHubAdvisoryClient';
import type { HttpResponse, IHttpClient } from '../../../src/application/ports/IHttpClient';
import { ClientHttpError, RateLimitHttpError } from '../../../src/application/ports/HttpRequestError';
import { PollingOrchestrator } from '../../../src/application/services/PollingOrchestrator';
import type { VulnerabilityFeed } from '../../../src/application/ports/VulnerabilityFeed';

test('extractNextLink parses GitHub Link header', () => {
  const link = '<https://api.github.com/advisories?page=2>; rel="next", <https://api.github.com/advisories?page=4>; rel="last"';
  assert.equal(extractNextLink(link), 'https://api.github.com/advisories?page=2');
});

test('extractNextLink returns undefined when next relation is missing', () => {
  const link = '<https://api.github.com/advisories?page=4>; rel="last"';
  assert.equal(extractNextLink(link), undefined);
});

const controls = { maxPages: 5, maxItems: 100 };

test('fetches global GitHub advisories with expected headers and endpoint', async () => {
  const seen: Array<{ url: string; headers: Record<string, string> }> = [];
  const httpClient: IHttpClient = {
    async getJson(url, headers) {
      seen.push({ url, headers });
      return {
        status: 200,
        headers: {},
        data: [{
          ghsa_id: 'GHSA-aaaa-bbbb-cccc',
          summary: 'Sample',
          description: 'desc',
          published_at: '2026-01-01T00:00:00.000Z',
          updated_at: '2026-01-02T00:00:00.000Z',
          severity: 'high',
          html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc'
        }]
      } as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', 'token-value', controls);
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });

  assert.equal(result.vulnerabilities.length, 1);
  assert.equal(seen.length, 1);
  assert.match(seen[0]?.url ?? '', /^https:\/\/api\.github\.com\/advisories\?/);
  assert.match(seen[0]?.url ?? '', /per_page=100/);
  assert.equal(seen[0]?.headers.Accept, 'application/vnd.github+json');
  assert.equal(seen[0]?.headers['X-GitHub-Api-Version'], '2022-11-28');
  assert.equal(seen[0]?.headers['User-Agent'], 'obsidian-vulndash');
  assert.equal(seen[0]?.headers.Authorization, 'Bearer token-value');
});

test('maps incremental cursor to GitHub updated filter', async () => {
  let seenUrl = '';
  const httpClient: IHttpClient = {
    async getJson(url) {
      seenUrl = url;
      return { status: 200, headers: {}, data: [] } as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  await client.fetchVulnerabilities({
    signal: new AbortController().signal,
    since: '2026-02-01T00:00:00.000Z'
  });

  assert.match(seenUrl, /updated=2026-02-01T00%3A00%3A00.000Z/);
});

test('handles empty advisory results', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return { status: 200, headers: {}, data: [] } as HttpResponse<never>;
    }
  };
  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });
  assert.equal(result.vulnerabilities.length, 0);
  assert.equal(result.pagesFetched, 1);
  assert.ok(result.warnings.includes('no_new_unique_records'));
});

test('paginates across link headers and deduplicates advisories', async () => {
  const responses: Array<HttpResponse<unknown>> = [
    {
      status: 200,
      headers: { link: '<https://api.github.com/advisories?page=2>; rel="next"' },
      data: [{ ghsa_id: 'GHSA-1', summary: 'one', published_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' }]
    },
    {
      status: 200,
      headers: {},
      data: [
        { ghsa_id: 'GHSA-1', summary: 'duplicate', published_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' },
        { ghsa_id: 'GHSA-2', summary: 'two', published_at: '2026-01-02T00:00:00.000Z', updated_at: '2026-01-02T00:00:00.000Z' }
      ]
    }
  ];

  const httpClient: IHttpClient = {
    async getJson() {
      const next = responses.shift();
      if (!next) throw new Error('unexpected request');
      return next as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });
  assert.equal(result.pagesFetched, 2);
  assert.deepEqual(result.vulnerabilities.map((item) => item.id), ['GHSA-1', 'GHSA-2']);
});

test('continues pagination after a page with zero new unique advisories', async () => {
  const responses: Array<HttpResponse<unknown>> = [
    {
      status: 200,
      headers: { link: '<https://api.github.com/advisories?page=2>; rel="next"' },
      data: [{ ghsa_id: 'GHSA-1', summary: 'one', published_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' }]
    },
    {
      status: 200,
      headers: { link: '<https://api.github.com/advisories?page=3>; rel="next"' },
      data: [{ ghsa_id: 'GHSA-1', summary: 'duplicate', published_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z' }]
    },
    {
      status: 200,
      headers: {},
      data: [{ ghsa_id: 'GHSA-2', summary: 'two', published_at: '2026-01-02T00:00:00.000Z', updated_at: '2026-01-02T00:00:00.000Z' }]
    }
  ];

  const httpClient: IHttpClient = {
    async getJson() {
      const next = responses.shift();
      if (!next) throw new Error('unexpected request');
      return next as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });
  assert.equal(result.pagesFetched, 3);
  assert.deepEqual(result.vulnerabilities.map((item) => item.id), ['GHSA-1', 'GHSA-2']);
  assert.ok(result.warnings.includes('no_new_unique_records'));
});

test('surfaces clear auth failure message', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      throw new ClientHttpError('HTTP 403', { status: 403, url: 'https://api.github.com/advisories' });
    }
  };
  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  await assert.rejects(
    () => client.fetchVulnerabilities({ signal: new AbortController().signal }),
    (error: unknown) => error instanceof ClientHttpError && error.message.includes('Configure a GitHub token')
  );
});

test('orchestrator retries on rate limiting', async () => {
  let attempts = 0;
  const feed: VulnerabilityFeed = {
    id: 'github-advisories-default',
    name: 'GitHub',
    async fetchVulnerabilities() {
      attempts += 1;
      if (attempts === 1) {
        throw new RateLimitHttpError('rate limited', { status: 429, url: 'https://api.github.com/advisories', retryAfterMs: 1 });
      }
      return { vulnerabilities: [], pagesFetched: 1, warnings: [], retriesPerformed: 0 };
    }
  };
  const orchestrator = new PollingOrchestrator([feed], {
    maxPages: 5,
    maxItems: 100,
    retryCount: 2,
    backoffBaseMs: 1,
    overlapWindowMs: 1_000,
    bootstrapLookbackMs: 60_000,
    debugHttpMetadata: false
  }, { cache: [], sourceSyncCursor: {} });

  const outcome = await orchestrator.pollOnce();
  assert.equal(outcome.results[0]?.success, true);
  assert.equal(outcome.results[0]?.retriesPerformed, 1);
});

test('cursor isolation uses feed.id even when names collide', async () => {
  const makeFeed = (id: string, mark: string): VulnerabilityFeed => ({
    id,
    name: 'GitHub',
    async fetchVulnerabilities() {
      return {
        vulnerabilities: [{
          id: mark,
          source: 'GitHub',
          title: mark,
          summary: mark,
          publishedAt: '2026-01-01T00:00:00.000Z',
          updatedAt: '2026-01-01T00:00:00.000Z',
          cvssScore: 0,
          severity: 'LOW',
          references: [],
          affectedProducts: []
        }],
        pagesFetched: 1,
        warnings: [],
        retriesPerformed: 0
      };
    }
  });

  const orchestrator = new PollingOrchestrator(
    [makeFeed('github-global', 'GHSA-1'), makeFeed('github-repo', 'GHSA-2')],
    {
      maxPages: 5,
      maxItems: 100,
      retryCount: 0,
      backoffBaseMs: 1,
      overlapWindowMs: 1_000,
      bootstrapLookbackMs: 60_000,
      debugHttpMetadata: false
    },
    { cache: [], sourceSyncCursor: {} }
  );
  const outcome = await orchestrator.pollOnce();
  assert.equal(typeof outcome.sourceSyncCursor['github-global'], 'string');
  assert.equal(typeof outcome.sourceSyncCursor['github-repo'], 'string');
});
