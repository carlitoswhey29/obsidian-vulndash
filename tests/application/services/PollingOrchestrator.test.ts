import test from 'node:test';
import assert from 'node:assert/strict';
import { PollingOrchestrator } from '../../../src/application/services/PollingOrchestrator';
import type { VulnerabilityFeed } from '../../../src/application/ports/VulnerabilityFeed';

const controls = {
  maxPages: 5,
  maxItems: 100,
  retryCount: 2,
  backoffBaseMs: 1,
  overlapWindowMs: 120_000,
  bootstrapLookbackMs: 86_400_000,
  debugHttpMetadata: false
};

test('advances cursor only on successful source sync', async () => {
  let githubUntil: string | undefined;
  const successFeed: VulnerabilityFeed = {
    id: 'github-default',
    name: 'GitHub',
    async fetchVulnerabilities(options) {
      githubUntil = options.until;
      return {
        vulnerabilities: [{
          id: 'GHSA-1', source: 'GitHub', title: 'one', summary: 'one',
          publishedAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-02T00:00:00.000Z',
          cvssScore: 8, severity: 'HIGH', references: [], affectedProducts: []
        }],
        pagesFetched: 1,
        warnings: [],
        retriesPerformed: 0
      };
    }
  };

  const failFeed: VulnerabilityFeed = {
    id: 'nvd-default',
    name: 'NVD',
    async fetchVulnerabilities() {
      throw new Error('boom');
    }
  };

  const orchestrator = new PollingOrchestrator([successFeed, failFeed], controls, {
    cache: [],
    sourceSyncCursor: { 'github-default': '2026-01-01T00:00:00.000Z', 'nvd-default': '2026-01-01T00:00:00.000Z' }
  });

  const outcome = await orchestrator.pollOnce();
  assert.equal(outcome.sourceSyncCursor['github-default'], githubUntil);
  assert.equal(outcome.sourceSyncCursor['nvd-default'], '2026-01-01T00:00:00.000Z');
});

test('idempotent merge keeps newest record', async () => {
  const feed: VulnerabilityFeed = {
    id: 'github-default',
    name: 'GitHub',
    async fetchVulnerabilities() {
      return {
        vulnerabilities: [
          {
            id: 'GHSA-1', source: 'GitHub', title: 'old', summary: 'old',
            publishedAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
            cvssScore: 5, severity: 'MEDIUM', references: [], affectedProducts: []
          },
          {
            id: 'GHSA-1', source: 'GitHub', title: 'new', summary: 'new',
            publishedAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-03T00:00:00.000Z',
            cvssScore: 9, severity: 'CRITICAL', references: [], affectedProducts: []
          }
        ],
        pagesFetched: 1,
        warnings: [],
        retriesPerformed: 0
      };
    }
  };

  const orchestrator = new PollingOrchestrator([feed], controls, { cache: [], sourceSyncCursor: {} });
  const outcome = await orchestrator.pollOnce();
  assert.equal(outcome.vulnerabilities.length, 1);
  assert.equal(outcome.vulnerabilities[0]?.title, 'new');
});

test('uses bootstrap lookback and fixed until window when cursor is missing', async () => {
  const calls: Array<{ since?: string; until?: string }> = [];
  const feed: VulnerabilityFeed = {
    id: 'nvd-default',
    name: 'NVD',
    async fetchVulnerabilities(options) {
      calls.push({
        ...(options.since ? { since: options.since } : {}),
        ...(options.until ? { until: options.until } : {})
      });
      return { vulnerabilities: [], pagesFetched: 1, warnings: [], retriesPerformed: 0 };
    }
  };

  const orchestrator = new PollingOrchestrator([feed], controls, { cache: [], sourceSyncCursor: {} });
  const outcome = await orchestrator.pollOnce();

  assert.equal(calls.length, 1);
  assert.equal(typeof calls[0]?.since, 'string');
  assert.equal(typeof calls[0]?.until, 'string');
  const sinceMs = Date.parse(calls[0]?.since ?? '');
  const untilMs = Date.parse(calls[0]?.until ?? '');
  assert.equal(untilMs - sinceMs, controls.bootstrapLookbackMs);
  assert.equal(outcome.sourceSyncCursor['nvd-default'], calls[0]?.until);
});

test('mixed outcome reports GitHub failure while retaining successful NVD data', async () => {
  const nvdFeed: VulnerabilityFeed = {
    id: 'nvd-default',
    name: 'NVD',
    async fetchVulnerabilities() {
      return {
        vulnerabilities: [{
          id: 'CVE-2026-0001', source: 'NVD', title: 'nvd item', summary: 'nvd item',
          publishedAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
          cvssScore: 8, severity: 'HIGH', references: [], affectedProducts: []
        }],
        pagesFetched: 1,
        warnings: [],
        retriesPerformed: 0
      };
    }
  };

  const githubFeed: VulnerabilityFeed = {
    id: 'github-default',
    name: 'GitHub',
    async fetchVulnerabilities() {
      throw new Error('github sync failed');
    }
  };

  const orchestrator = new PollingOrchestrator([nvdFeed, githubFeed], controls, { cache: [], sourceSyncCursor: {} });
  const outcome = await orchestrator.pollOnce();

  assert.equal(outcome.vulnerabilities.length, 1);
  assert.equal(outcome.results.length, 2);
  assert.equal(outcome.results[0]?.source, 'NVD');
  assert.equal(outcome.results[0]?.success, true);
  assert.equal(outcome.results[1]?.source, 'GitHub');
  assert.equal(outcome.results[1]?.success, false);
  assert.equal(outcome.results[1]?.errorSummary, 'github sync failed');
});
