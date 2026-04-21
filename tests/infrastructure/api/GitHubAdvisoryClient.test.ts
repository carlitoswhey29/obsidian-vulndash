import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubAdvisoryClient, extractNextLink } from '../../../src/infrastructure/clients/github/GitHubAdvisoryClient';
import type { HttpResponse, IHttpClient } from '../../../src/application/ports/HttpClient';
import { AuthFailureHttpError, ClientHttpError, RateLimitHttpError } from '../../../src/application/ports/DataSourceError';
import { PollingOrchestrator } from '../../../src/application/use-cases/SyncJobScheduler';
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

test('normalizes GitHub advisory package and identifier metadata', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: [{
          ghsa_id: 'GHSA-aaaa-bbbb-cccc',
          cve_id: 'CVE-2026-1234',
          url: 'https://api.github.com/advisories/GHSA-aaaa-bbbb-cccc',
          html_url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
          repository_advisory_url: 'https://api.github.com/repos/acme/widget/security-advisories/GHSA-aaaa-bbbb-cccc',
          summary: 'Sample',
          description: 'desc',
          published_at: '2026-01-01T00:00:00.000Z',
          updated_at: '2026-01-02T00:00:00.000Z',
          severity: 'critical',
          identifiers: [
            { type: 'GHSA', value: 'GHSA-aaaa-bbbb-cccc' },
            { type: 'CVE', value: 'CVE-2026-1234' }
          ],
          cwes: [{ cwe_id: 'CWE-79', name: 'Cross-site Scripting' }],
          vulnerabilities: [{
            package: { ecosystem: 'npm', name: '@acme/widget' },
            vulnerable_version_range: '< 1.2.3',
            first_patched_version: { identifier: '1.2.3' },
            vulnerable_functions: ['parseWidget', 'parseWidget'],
            source_code_location: 'https://github.com/acme/widget'
          }],
          references: ['https://example.com/advisory']
        }]
      } as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });
  const vulnerability = result.vulnerabilities[0];

  assert.equal(vulnerability?.metadata?.ghsaId, 'GHSA-aaaa-bbbb-cccc');
  assert.equal(vulnerability?.metadata?.cveId, 'CVE-2026-1234');
  assert.deepEqual(vulnerability?.metadata?.identifiers, ['GHSA-aaaa-bbbb-cccc', 'CVE-2026-1234']);
  assert.deepEqual(vulnerability?.metadata?.cwes, ['CWE-79']);
  assert.deepEqual(vulnerability?.metadata?.vendors, ['acme']);
  assert.deepEqual(vulnerability?.metadata?.packages, ['@acme/widget']);
  assert.deepEqual(vulnerability?.metadata?.vulnerableVersionRanges, ['@acme/widget: < 1.2.3']);
  assert.deepEqual(vulnerability?.metadata?.firstPatchedVersions, ['@acme/widget: 1.2.3']);
  assert.deepEqual(vulnerability?.metadata?.vulnerableFunctions, ['parseWidget']);
  assert.equal(vulnerability?.metadata?.affectedPackages?.[0]?.ecosystem, 'npm');
  assert.equal(vulnerability?.metadata?.affectedPackages?.[0]?.sourceCodeLocation, 'https://github.com/acme/widget');
  assert.ok(vulnerability?.references.includes('https://github.com/advisories/GHSA-aaaa-bbbb-cccc'));
  assert.ok(vulnerability?.references.includes('https://example.com/advisory'));
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

  assert.match(seenUrl, /since=2026-02-01T00%3A00%3A00.000Z/);
});

test('filters GitHub advisories by explicit published window after fetch', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: [
          { ghsa_id: 'GHSA-1', summary: 'one', published_at: '2026-04-18T00:00:00.000Z', updated_at: '2026-04-18T00:00:00.000Z' },
          { ghsa_id: 'GHSA-2', summary: 'two', published_at: '2026-04-21T00:00:00.000Z', updated_at: '2026-04-21T00:00:00.000Z' }
        ]
      } as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  const result = await client.fetchVulnerabilities({
    signal: new AbortController().signal,
    publishedFrom: '2026-04-20T00:00:00.000Z',
    publishedUntil: '2026-04-21T23:59:59.999Z'
  });

  assert.deepEqual(result.vulnerabilities.map((item) => item.id), ['GHSA-2']);
});

test('filters GitHub advisories by explicit modified window after fetch', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: [
          { ghsa_id: 'GHSA-1', summary: 'one', published_at: '2026-04-10T00:00:00.000Z', updated_at: '2026-04-18T00:00:00.000Z' },
          { ghsa_id: 'GHSA-2', summary: 'two', published_at: '2026-04-10T00:00:00.000Z', updated_at: '2026-04-21T00:00:00.000Z' }
        ]
      } as HttpResponse<never>;
    }
  };

  const client = new GitHubAdvisoryClient(httpClient, 'github-advisories-default', 'GitHub', '', controls);
  const result = await client.fetchVulnerabilities({
    signal: new AbortController().signal,
    modifiedFrom: '2026-04-20T00:00:00.000Z',
    modifiedUntil: '2026-04-21T23:59:59.999Z'
  });

  assert.deepEqual(result.vulnerabilities.map((item) => item.id), ['GHSA-2']);
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
    (error: unknown) => error instanceof AuthFailureHttpError && error.message.includes('Configure a GitHub token')
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
