import assert from 'node:assert/strict';
import test from 'node:test';
import { IngestionPipeline } from '../../../src/application/pipeline/IngestionPipeline';
import type { PipelineEvent } from '../../../src/application/pipeline/PipelineEvents';
import { PipelineRunRegistry } from '../../../src/application/pipeline/PipelineRunRegistry';
import type { PipelineRunId } from '../../../src/application/pipeline/PipelineTypes';
import { buildVulnerabilityCacheKey } from '../../../src/application/pipeline/PipelineTypes';
import type { VulnerabilityFeed } from '../../../src/application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

const controls = {
  maxPages: 5,
  maxItems: 100,
  retryCount: 2,
  backoffBaseMs: 1,
  overlapWindowMs: 120_000,
  bootstrapLookbackMs: 86_400_000,
  debugHttpMetadata: false
};

const createVulnerability = (
  id: string,
  overrides: Partial<Vulnerability> = {}
): Vulnerability => ({
  affectedProducts: [],
  cvssScore: 7.5,
  id,
  publishedAt: '2026-01-01T00:00:00.000Z',
  references: [],
  severity: 'HIGH',
  source: 'GitHub',
  summary: `${id} summary`,
  title: `${id} title`,
  updatedAt: '2026-01-01T00:00:00.000Z',
  ...overrides
});

test('pipeline chunks large payloads and emits explicit stage events', async () => {
  const events: PipelineEvent[] = [];
  const pipeline = new IngestionPipeline({ chunkSize: 2 });
  const feed: VulnerabilityFeed = {
    id: 'github-default',
    name: 'GitHub',
    async fetchVulnerabilities() {
      return {
        pagesFetched: 1,
        retriesPerformed: 0,
        vulnerabilities: [
          createVulnerability('GHSA-OLD', { updatedAt: '2026-01-01T00:00:00.000Z' }),
          createVulnerability('GHSA-2', { publishedAt: '2026-01-02T00:00:00.000Z', updatedAt: '2026-01-02T00:00:00.000Z' }),
          createVulnerability('GHSA-OLD', { title: 'newer duplicate', updatedAt: '2026-01-03T00:00:00.000Z' }),
          createVulnerability('GHSA-3', { publishedAt: '2026-01-04T00:00:00.000Z', updatedAt: '2026-01-04T00:00:00.000Z' })
        ],
        warnings: []
      };
    }
  };

  const result = await pipeline.run({
    controls,
    onEvent: async (event) => {
      events.push(event);
    },
    snapshot: {
      cacheByKey: new Map(),
      originByKey: new Map()
    },
    source: {
      runId: 'github-default:1' as PipelineRunId,
      since: '2026-01-01T00:00:00.000Z',
      sourceId: 'github-default',
      sourceName: 'GitHub',
      syncMode: 'incremental',
      until: '2026-01-05T00:00:00.000Z'
    },
    sourceFeed: feed
  });

  assert.deepEqual(events.map((event) => event.stage), ['fetch', 'transform', 'merge', 'notify', 'transform', 'merge', 'notify']);
  assert.deepEqual(
    events
      .filter((event): event is Extract<PipelineEvent, { stage: 'transform' }> => event.stage === 'transform')
      .map((event) => event.input.vulnerabilities.length),
    [2, 2]
  );
  assert.equal(result.itemsDeduplicated, 1);
  assert.equal(result.vulnerabilities.length, 3);
  assert.equal(result.vulnerabilities[0]?.id, 'GHSA-3');
  assert.equal(result.vulnerabilities.find((item) => item.id === 'GHSA-OLD')?.title, 'newer duplicate');
});

test('pipeline snapshot mode reports removed ids without touching other feed entries', async () => {
  const pipeline = new IngestionPipeline({ chunkSize: 2 });
  const existing = createVulnerability('GHSA-KEEP', { publishedAt: '2026-01-02T00:00:00.000Z' });
  const removed = createVulnerability('GHSA-REMOVE');
  const otherFeed = createVulnerability('CVE-2026-1', { source: 'NVD' });

  const result = await pipeline.run({
    controls,
    snapshot: {
      cacheByKey: new Map([
        [buildVulnerabilityCacheKey(existing), existing],
        [buildVulnerabilityCacheKey(removed), removed],
        [buildVulnerabilityCacheKey(otherFeed), otherFeed]
      ]),
      originByKey: new Map([
        [buildVulnerabilityCacheKey(existing), 'github-default'],
        [buildVulnerabilityCacheKey(removed), 'github-default'],
        [buildVulnerabilityCacheKey(otherFeed), 'nvd-default']
      ])
    },
    source: {
      runId: 'github-default:2' as PipelineRunId,
      sourceId: 'github-default',
      sourceName: 'GitHub',
      syncMode: 'snapshot',
      until: '2026-01-05T00:00:00.000Z'
    },
    sourceFeed: {
      id: 'github-default',
      name: 'GitHub',
      async fetchVulnerabilities() {
        return {
          pagesFetched: 1,
          retriesPerformed: 0,
          vulnerabilities: [existing],
          warnings: []
        };
      }
    }
  });

  assert.deepEqual(result.changedIds.removed, [buildVulnerabilityCacheKey(removed)]);
  assert.equal(result.vulnerabilities.some((item) => item.id === 'GHSA-REMOVE'), false);
  assert.equal(result.vulnerabilities.some((item) => item.id === 'CVE-2026-1'), true);
});

test('run registry marks older runs stale once a newer generation starts', () => {
  const registry = new PipelineRunRegistry();
  const first = registry.start('github-default');
  const second = registry.start('github-default');

  assert.equal(registry.isCurrent(first), false);
  assert.equal(registry.isCurrent(second), true);

  registry.finish(second);
  assert.equal(registry.isCurrent(second), false);
});
