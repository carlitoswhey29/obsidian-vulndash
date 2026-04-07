import test from 'node:test';
import assert from 'node:assert/strict';
import { PollingOrchestrator } from './PollingOrchestrator';
import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';

const controls = {
  maxPages: 5,
  maxItems: 100,
  retryCount: 2,
  backoffBaseMs: 1,
  overlapWindowMs: 120_000,
  debugHttpMetadata: false
};

test('advances cursor only on successful source sync', async () => {
  const successFeed: VulnerabilityFeed = {
    name: 'GitHub',
    async fetchVulnerabilities() {
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
    name: 'NVD',
    async fetchVulnerabilities() {
      throw new Error('boom');
    }
  };

  const orchestrator = new PollingOrchestrator([successFeed, failFeed], controls, {
    cache: [],
    sourceSyncCursor: { GitHub: '2026-01-01T00:00:00.000Z', NVD: '2026-01-01T00:00:00.000Z' }
  });

  const outcome = await orchestrator.pollOnce();
  assert.equal(outcome.sourceSyncCursor.GitHub, '2026-01-02T00:00:00.000Z');
  assert.equal(outcome.sourceSyncCursor.NVD, '2026-01-01T00:00:00.000Z');
});

test('idempotent merge keeps newest record', async () => {
  const feed: VulnerabilityFeed = {
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
