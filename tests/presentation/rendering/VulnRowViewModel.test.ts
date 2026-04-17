import assert from 'node:assert/strict';
import test from 'node:test';
import type { RelatedComponentSummary } from '../../../src/application/sbom/types';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { areVulnRowViewModelsEqual, buildVulnRowViewModel } from '../../../src/presentation/rendering/VulnRowViewModel';

const createVulnerability = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  affectedProducts: ['demo-app'],
  cvssScore: 8.1,
  id: 'CVE-2026-0001',
  publishedAt: '2026-04-01T12:00:00.000Z',
  updatedAt: '2026-04-02T12:00:00.000Z',
  references: ['https://example.com/advisories/CVE-2026-0001'],
  severity: 'HIGH',
  source: 'NVD',
  summary: 'A test summary',
  title: 'Demo vulnerability',
  ...overrides
});

const createRelatedComponent = (overrides: Partial<RelatedComponentSummary> = {}): RelatedComponentSummary => ({
  key: 'pkg:npm/demo-app@1.0.0',
  evidence: 'purl',
  name: 'demo-app',
  vulnerabilityCount: 1,
  ...overrides
});

const buildRow = (overrides: Parameters<typeof buildVulnRowViewModel>[1] = {
  colorCodedSeverity: true,
  columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
  expanded: false,
  getRowKey: (item) => `${item.source}:${item.id}`,
  isNew: false,
  relatedComponents: [],
  triagePending: false,
  triageState: 'active'
}) => buildVulnRowViewModel(createVulnerability(), overrides);

test('row view-model equality stays stable for identical rendered data', () => {
  const left = buildRow();
  const right = buildRow();

  assert.equal(areVulnRowViewModelsEqual(left, right), true);
});

test('row view-model equality detects rendered severity-style and related-component changes', () => {
  const vulnerability = createVulnerability();
  const base = buildVulnRowViewModel(vulnerability, {
    colorCodedSeverity: true,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: true,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: [createRelatedComponent()],
    triagePending: false,
    triageState: 'active'
  });
  const changed = buildVulnRowViewModel(vulnerability, {
    colorCodedSeverity: false,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: true,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: [createRelatedComponent({ evidence: 'explicit' })],
    triagePending: false,
    triageState: 'active'
  });

  assert.equal(areVulnRowViewModelsEqual(base, changed), false);
});

test('row view-model equality detects triage-state and pending changes', () => {
  const base = buildRow({
    colorCodedSeverity: true,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: false,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: [],
    triagePending: false,
    triageState: 'active'
  });
  const changed = buildRow({
    colorCodedSeverity: true,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: false,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: [],
    triagePending: true,
    triageState: 'mitigated'
  });

  assert.equal(areVulnRowViewModelsEqual(base, changed), false);
});
