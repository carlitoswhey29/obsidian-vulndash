import test from 'node:test';
import assert from 'node:assert/strict';
import { GitHubRepoClient } from '../../../../src/infrastructure/clients/github/GitHubRepoClient';
import type { HttpResponse, IHttpClient } from '../../../../src/application/ports/IHttpClient';

const controls = { maxPages: 5, maxItems: 100 };

test('fetches repo advisories with normalized repo filter and auth header', async () => {
  let seenUrl = '';
  let seenHeaders: Record<string, string> | undefined;

  const httpClient: IHttpClient = {
    async getJson(url, headers) {
      seenUrl = url;
      seenHeaders = headers;

      return {
        status: 200,
        headers: {},
        data: []
      } as HttpResponse<never>;
    }
  };

  const client = new GitHubRepoClient(
    httpClient,
    'github-repo-default',
    'GitHub Repo',
    'token-value',
    ' OpenAI/ChatGPT ',
    controls
  );

  const result = await client.fetchVulnerabilities({
    signal: new AbortController().signal,
    since: '2026-04-15T00:00:00.000Z'
  });

  assert.equal(result.pagesFetched, 1);
  assert.match(seenUrl, /^https:\/\/api\.github\.com\/advisories\?/);
  assert.match(seenUrl, /affects=openai%2Fchatgpt/);
  assert.match(seenUrl, /updated=2026-04-15T00%3A00%3A00.000Z/);
  assert.equal(seenHeaders?.Accept, 'application/vnd.github+json');
  assert.equal(seenHeaders?.Authorization, 'Bearer token-value');
});

test('normalizes repo advisories and deduplicates affected products', async () => {
  const httpClient: IHttpClient = {
    async getJson() {
      return {
        status: 200,
        headers: {},
        data: [{
          ghsa_id: 'GHSA-repo-1234',
          summary: 'Repo advisory',
          description: 'Repository specific advisory details',
          published_at: '2026-04-15T00:00:00.000Z',
          updated_at: '2026-04-15T01:00:00.000Z',
          severity: 'high',
          html_url: 'https://github.com/advisories/GHSA-repo-1234',
          vulnerabilities: [
            { package: { name: 'widget' } },
            { package: { name: 'widget' } },
            { package: { name: 'widget-api' } }
          ]
        }]
      } as HttpResponse<never>;
    }
  };

  const client = new GitHubRepoClient(
    httpClient,
    'github-repo-default',
    'GitHub Repo',
    '',
    'openai/chatgpt',
    controls
  );

  const result = await client.fetchVulnerabilities({ signal: new AbortController().signal });
  const vulnerability = result.vulnerabilities[0];

  assert.equal(vulnerability?.id, 'GHSA-repo-1234');
  assert.equal(vulnerability?.source, 'GitHub:openai/chatgpt');
  assert.equal(vulnerability?.severity, 'HIGH');
  assert.deepEqual(vulnerability?.references, ['https://github.com/advisories/GHSA-repo-1234']);
  assert.deepEqual(vulnerability?.affectedProducts, ['widget', 'widget-api']);
});
