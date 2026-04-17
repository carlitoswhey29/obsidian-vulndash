import assert from 'node:assert/strict';
import test from 'node:test';
import type { RelatedComponentSummary } from '../../../src/application/sbom/types';
import { EMPTY_AFFECTED_PROJECT_RESOLUTION } from '../../../src/domain/correlation/AffectedProjectResolution';
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

const createOptions = (overrides: Partial<Parameters<typeof buildVulnRowViewModel>[1]> = {}): Parameters<typeof buildVulnRowViewModel>[1] => ({
  affectedProjectResolution: EMPTY_AFFECTED_PROJECT_RESOLUTION,
  colorCodedSeverity: true,
  columns: [{ key: 'id', label: 'ID' }, { key: 'severity', label: 'Severity' }],
  expanded: false,
  getRowKey: (item) => `${item.source}:${item.id}`,
  isNew: false,
  relatedComponents: [],
  triagePending: false,
  triageState: 'active',
  ...overrides
});

const buildRow = (overrides: Partial<Parameters<typeof buildVulnRowViewModel>[1]> = {}) =>
  buildVulnRowViewModel(createVulnerability(), createOptions(overrides));

test('row view-model equality stays stable for identical rendered data', () => {
  const left = buildRow();
  const right = buildRow();

  assert.equal(areVulnRowViewModelsEqual(left, right), true);
});

test('row view-model equality detects rendered severity-style and related-component changes', () => {
  const vulnerability = createVulnerability();
  const base = buildVulnRowViewModel(vulnerability, createOptions({
    expanded: true,
    relatedComponents: [createRelatedComponent()]
  }));
  const changed = buildVulnRowViewModel(vulnerability, createOptions({
    colorCodedSeverity: false,
    expanded: true,
    relatedComponents: [createRelatedComponent({ evidence: 'explicit' })]
  }));

  assert.equal(areVulnRowViewModelsEqual(base, changed), false);
});

test('row view-model equality detects triage-state and pending changes', () => {
  const base = buildRow();
  const changed = buildRow({
    triagePending: true,
    triageState: 'mitigated'
  });

  assert.equal(areVulnRowViewModelsEqual(base, changed), false);
});

test('row view-model equality detects affected-project rendering changes', () => {
  const base = buildRow({
    affectedProjectResolution: {
      affectedProjects: [{
        displayName: 'Portal Platform',
        notePath: 'Projects/Portal.md',
        sourceSbomIds: ['sbom-1'],
        sourceSbomLabels: ['Portal SBOM'],
        status: 'linked'
      }],
      unmappedSboms: []
    }
  });
  const changed = buildRow({
    affectedProjectResolution: {
      affectedProjects: [{
        displayName: 'Portal Platform',
        notePath: 'Projects/Portal.md',
        sourceSbomIds: ['sbom-1'],
        sourceSbomLabels: ['Portal SBOM'],
        status: 'broken'
      }],
      unmappedSboms: [{
        sbomId: 'sbom-2',
        sbomLabel: 'Gateway SBOM'
      }]
    }
  });

  assert.equal(areVulnRowViewModelsEqual(base, changed), false);
});
