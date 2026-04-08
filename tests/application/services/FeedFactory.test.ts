import test from 'node:test';
import assert from 'node:assert/strict';
import type { IHttpClient, HttpResponse } from '../../../src/application/ports/IHttpClient';
import { buildFeedsFromConfig } from '../../../src/application/services/FeedFactory';
import type { FeedConfig } from '../../../src/application/services/types';

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
    { id: 'nvd-default', name: 'NVD', type: 'nvd', enabled: true, apiKey: 'k' },
    { id: 'github-default', name: 'GitHub', type: 'github_advisory', enabled: false, token: 'x' },
    { id: 'repo-feed', name: 'Repo feed', type: 'github_repo', enabled: true, repoPath: 'Owner/Repo', token: 'x' },
    { id: 'generic-invalid', name: 'Custom', type: 'generic_json', enabled: true, url: '   ' }
  ];

  const feeds = buildFeedsFromConfig(configs, httpClient, controls);

  assert.equal(feeds.length, 2);
  assert.deepEqual(feeds.map((feed) => feed.id), ['nvd-default', 'repo-feed']);
});
