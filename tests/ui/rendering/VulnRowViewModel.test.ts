import assert from 'node:assert/strict';
import test from 'node:test';
import type { RelatedComponentSummary } from '../../../src/application/sbom/types';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { areVulnRowViewModelsEqual, buildVulnRowViewModel } from '../../../src/ui/rendering/VulnRowViewModel';

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

test('row view-model equality stays stable for identical rendered data', () => {
  const vulnerability = createVulnerability();
  const left = buildVulnRowViewModel(vulnerability, {
    colorCodedSeverity: true,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: false,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: []
  });
  const right = buildVulnRowViewModel(vulnerability, {
    colorCodedSeverity: true,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: false,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: []
  });

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
    relatedComponents: [createRelatedComponent()]
  });
  const changed = buildVulnRowViewModel(vulnerability, {
    colorCodedSeverity: false,
    columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
    expanded: true,
    getRowKey: (item) => `${item.source}:${item.id}`,
    isNew: false,
    relatedComponents: [createRelatedComponent({ evidence: 'explicit' })]
  });

  assert.equal(areVulnRowViewModelsEqual(base, changed), false);
});

