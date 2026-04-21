import assert from 'node:assert/strict';
import test from 'node:test';
import {
  DEFAULT_DASHBOARD_DATE_RANGE,
  filterVulnerabilitiesByPublishedDateWindow,
  resolveDashboardDateRangeSelection
} from '../../../src/application/dashboard/PublishedDateWindow';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

const createVulnerability = (id: string, publishedAt: string): Vulnerability => ({
  affectedProducts: ['demo'],
  cvssScore: 7.5,
  id,
  publishedAt,
  references: [],
  severity: 'HIGH',
  source: 'NVD',
  summary: 'demo',
  title: id,
  updatedAt: publishedAt
});

test('default dashboard date range resolves to a rolling past-day window', () => {
  const now = new Date('2026-04-21T15:30:00.000Z');
  const resolution = resolveDashboardDateRangeSelection(DEFAULT_DASHBOARD_DATE_RANGE, now);

  assert.equal(resolution.isValid, true);
  assert.equal(resolution.window?.to, '2026-04-21T15:30:00.000Z');
  assert.equal(resolution.window?.from, '2026-04-20T15:30:00.000Z');
});

test('custom dashboard date range normalizes to local full-day boundaries', () => {
  const resolution = resolveDashboardDateRangeSelection({
    preset: 'custom',
    customFrom: '2026-04-10',
    customTo: '2026-04-12'
  });

  assert.equal(resolution.isValid, true);
  assert.match(resolution.window?.from ?? '', /^2026-04-10T/);
  assert.match(resolution.window?.to ?? '', /^2026-04-13T|^2026-04-12T/);
  assert.ok((resolution.window?.from ?? '').endsWith('Z'));
  assert.ok((resolution.window?.to ?? '').endsWith('Z'));
});

test('custom dashboard date range validates required dates and ordering', () => {
  const missing = resolveDashboardDateRangeSelection({
    preset: 'custom',
    customFrom: '2026-04-10'
  });
  assert.equal(missing.isValid, false);
  assert.equal(missing.validationMessage, 'Both From and To dates are required.');

  const reversed = resolveDashboardDateRangeSelection({
    preset: 'custom',
    customFrom: '2026-04-12',
    customTo: '2026-04-10'
  });
  assert.equal(reversed.isValid, false);
  assert.equal(reversed.validationMessage, 'From date must be on or before the To date.');
});

test('published date window filter keeps only findings inside the inclusive window', () => {
  const vulnerabilities = [
    createVulnerability('CVE-1', '2026-04-20T00:00:00.000Z'),
    createVulnerability('CVE-2', '2026-04-21T10:30:00.000Z'),
    createVulnerability('CVE-3', '2026-04-22T00:00:00.000Z')
  ];

  const filtered = filterVulnerabilitiesByPublishedDateWindow(vulnerabilities, {
    from: '2026-04-20T00:00:00.000Z',
    to: '2026-04-21T23:59:59.999Z'
  });

  assert.deepEqual(filtered.map((vulnerability) => vulnerability.id), ['CVE-1', 'CVE-2']);
});
