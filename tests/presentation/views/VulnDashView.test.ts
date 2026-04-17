import assert from 'node:assert/strict';
import test from 'node:test';
import { FilterByAffectedProject } from '../../../src/application/correlation/FilterByAffectedProject';
import { EMPTY_AFFECTED_PROJECT_RESOLUTION } from '../../../src/domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

const createVulnerability = (id: string): Vulnerability => ({
  affectedProducts: ['demo'],
  cvssScore: 7.5,
  id,
  publishedAt: '2026-04-01T00:00:00.000Z',
  references: [],
  severity: 'HIGH',
  source: 'NVD',
  summary: 'demo',
  title: id,
  updatedAt: '2026-04-01T00:00:00.000Z'
});

test('view filtering can target a mapped project note path', () => {
  const vulnerabilities = [createVulnerability('CVE-1'), createVulnerability('CVE-2')];
  const resolutions = new Map([
    ['CVE-1', {
      affectedProjects: [{
        displayName: 'Portal Platform',
        notePath: 'Projects/Portal.md',
        sourceSbomIds: ['sbom-1'],
        sourceSbomLabels: ['Portal SBOM'],
        status: 'linked' as const
      }],
      unmappedSboms: []
    }],
    ['CVE-2', {
      affectedProjects: [],
      unmappedSboms: [{ sbomId: 'sbom-2', sbomLabel: 'Gateway SBOM' }]
    }]
  ]);

  const filtered = new FilterByAffectedProject().execute(vulnerabilities, {
    kind: 'project',
    notePath: 'Projects/Portal.md'
  }, (vulnerability) => resolutions.get(vulnerability.id) ?? EMPTY_AFFECTED_PROJECT_RESOLUTION);

  assert.deepEqual(filtered.map((item) => item.id), ['CVE-1']);
});

test('view filtering can isolate unmapped findings', () => {
  const vulnerabilities = [createVulnerability('CVE-1'), createVulnerability('CVE-2')];
  const resolutions = new Map([
    ['CVE-1', EMPTY_AFFECTED_PROJECT_RESOLUTION],
    ['CVE-2', {
      affectedProjects: [],
      unmappedSboms: [{ sbomId: 'sbom-2', sbomLabel: 'Gateway SBOM' }]
    }]
  ]);

  const filtered = new FilterByAffectedProject().execute(vulnerabilities, {
    kind: 'unmapped'
  }, (vulnerability) => resolutions.get(vulnerability.id) ?? EMPTY_AFFECTED_PROJECT_RESOLUTION);

  assert.deepEqual(filtered.map((item) => item.id), ['CVE-2']);
});

