import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildFailureNoticeMessage,
  buildVisibilityDiagnostics,
  getFailedFeedNames,
  summarizeSyncResults
} from '../../../src/application/services/SyncOutcomeDiagnostics';
import type { SyncResult } from '../../../src/application/services/PollingOrchestrator';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

const makeResult = (result: Partial<SyncResult> & Pick<SyncResult, 'source' | 'success'>): SyncResult => ({
  feedId: result.feedId ?? result.source.toLowerCase(),
  source: result.source,
  startedAt: result.startedAt ?? '2026-04-08T00:00:00.000Z',
  completedAt: result.completedAt ?? '2026-04-08T00:00:01.000Z',
  success: result.success,
  itemsFetched: result.itemsFetched ?? 0,
  itemsMerged: result.itemsMerged ?? 0,
  itemsDeduplicated: result.itemsDeduplicated ?? 0,
  pagesFetched: result.pagesFetched ?? 0,
  retriesPerformed: result.retriesPerformed ?? 0,
  warnings: result.warnings ?? [],
  ...(result.errorSummary ? { errorSummary: result.errorSummary } : {}),
  ...(result.authFailure ? { authFailure: result.authFailure } : {})
});

const makeVulnerability = (id: string, source: string): Vulnerability => ({
  id,
  source,
  title: id,
  summary: id,
  publishedAt: '2026-04-08T00:00:00.000Z',
  updatedAt: '2026-04-08T00:00:00.000Z',
  cvssScore: 7,
  severity: 'HIGH',
  references: [],
  affectedProducts: []
});

test('summarizes sync outcomes and surfaces failing feeds', () => {
  const results = [
    makeResult({ source: 'NVD', success: true, itemsFetched: 12, pagesFetched: 2, warnings: [] }),
    makeResult({ source: 'GitHub', success: false, errorSummary: '403 forbidden', pagesFetched: 1, warnings: ['rate_limited'] })
  ];

  const summaries = summarizeSyncResults(results);
  assert.equal(summaries.length, 2);
  assert.deepEqual(getFailedFeedNames(results), ['GitHub']);
  assert.equal(buildFailureNoticeMessage(results), 'VulnDash sync failed for: GitHub. Check logs for details.');
  assert.equal(summaries[1]?.errorSummary, '403 forbidden');
});

test('auth failure notice explains expired revoked or permission problem', () => {
  const results = [
    makeResult({
      source: 'GitHub',
      success: false,
      errorSummary: 'Authentication failed. Token or API key may be expired, revoked, or invalid.',
      authFailure: { reason: 'unauthorized' }
    })
  ];

  assert.equal(
    buildFailureNoticeMessage(results),
    'VulnDash authentication failed for: GitHub. Token or API key may be expired, revoked, invalid, or missing required permissions.'
  );
  assert.equal(summarizeSyncResults(results)[0]?.authFailure?.reason, 'unauthorized');
});

test('mixed success keeps failure notice focused on failed feed', () => {
  const results = [
    makeResult({ source: 'NVD', success: true, itemsFetched: 30, pagesFetched: 3 }),
    makeResult({ source: 'GitHub', success: false, errorSummary: 'token invalid', pagesFetched: 0 })
  ];

  assert.equal(buildFailureNoticeMessage(results), 'VulnDash sync failed for: GitHub. Check logs for details.');
});

test('filtered-out advisories are distinguishable from fetch failures', () => {
  const results = [
    makeResult({ source: 'GitHub', success: true, itemsFetched: 5, pagesFetched: 1, warnings: ['no_new_unique_records'] })
  ];

  const fetched = [
    makeVulnerability('GHSA-1', 'GitHub'),
    makeVulnerability('GHSA-2', 'GitHub'),
    makeVulnerability('CVE-1', 'NVD')
  ];
  const visible: Vulnerability[] = [];

  const diagnostics = buildVisibilityDiagnostics(fetched, visible);
  assert.equal(buildFailureNoticeMessage(results), undefined);
  assert.equal(diagnostics.totalFetched, 3);
  assert.equal(diagnostics.totalVisible, 0);
  assert.equal(diagnostics.filteredOut, 3);
  assert.equal(diagnostics.fetchedBySource.GitHub, 2);
  assert.equal(diagnostics.fetchedBySource.NVD, 1);
});
