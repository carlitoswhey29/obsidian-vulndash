import assert from 'node:assert/strict';
import test from 'node:test';
import { ResolveAffectedProjects, type ProjectNoteLookup } from '../../../src/application/correlation/ResolveAffectedProjects';
import type { ComponentRelationshipGraph } from '../../../src/application/sbom/types';
import { createProjectNoteReference } from '../../../src/domain/correlation/ProjectNoteReference';
import type { SbomProjectMappingRepository } from '../../../src/domain/correlation/SbomProjectMappingRepository';
import { createSbomProjectMapping } from '../../../src/domain/correlation/SbomProjectMapping';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

const createVulnerability = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  affectedProducts: ['portal'],
  cvssScore: 9.1,
  id: 'CVE-2026-1000',
  publishedAt: '2026-04-10T00:00:00.000Z',
  references: [],
  severity: 'CRITICAL',
  source: 'NVD',
  summary: 'demo',
  title: 'demo vuln',
  updatedAt: '2026-04-10T00:00:00.000Z',
  ...overrides
});

const repository: SbomProjectMappingRepository = {
  deleteBySbomId: async () => undefined,
  getBySbomId: async () => null,
  list: async () => [
    createSbomProjectMapping('sbom-1', createProjectNoteReference('Projects/Portal.md', 'Portal Platform')),
    createSbomProjectMapping('sbom-2', createProjectNoteReference('Projects/Portal.md', 'Portal Platform')),
    createSbomProjectMapping('sbom-4', createProjectNoteReference('Projects/Missing.md', 'Legacy Platform'))
  ],
  replaceNotePath: async () => 0,
  save: async () => undefined
};

const lookup: ProjectNoteLookup = {
  getByPaths: async () => new Map([
    ['Projects/Portal.md', {
      displayName: 'Portal Platform',
      notePath: 'Projects/Portal.md',
      status: 'linked'
    }],
    ['Projects/Missing.md', {
      displayName: 'Legacy Platform',
      notePath: 'Projects/Missing.md',
      status: 'broken'
    }]
  ])
};

test('ResolveAffectedProjects deduplicates shared project notes and surfaces unmapped sboms', async () => {
  const resolver = new ResolveAffectedProjects(repository, lookup);
  const vulnerability = createVulnerability();
  const graph: ComponentRelationshipGraph = {
    componentsByVulnerability: new Map([[
      'nvd::cve-2026-1000',
      [{
        evidence: 'purl',
        key: 'pkg:npm/portal@1.0.0',
        name: 'portal',
        vulnerabilityCount: 1
      }]
    ]]),
    relationships: [],
    vulnerabilitiesByComponent: new Map()
  };

  const result = await resolver.execute({
    componentIndex: {
      getSbomIdsForComponent: () => ['sbom-1', 'sbom-2', 'sbom-3']
    },
    relationships: graph,
    sboms: [
      { id: 'sbom-1', label: 'Portal API' },
      { id: 'sbom-2', label: 'Portal Web' },
      { id: 'sbom-3', label: 'Gateway' }
    ],
    vulnerabilities: [vulnerability]
  });

  const resolution = result.get('nvd::cve-2026-1000');
  assert.ok(resolution);
  assert.equal(resolution?.affectedProjects.length, 1);
  assert.deepEqual(resolution?.affectedProjects[0]?.sourceSbomLabels, ['Portal API', 'Portal Web']);
  assert.deepEqual(resolution?.unmappedSboms, [{ sbomId: 'sbom-3', sbomLabel: 'Gateway' }]);
});

test('ResolveAffectedProjects preserves broken note mappings for repair flows', async () => {
  const resolver = new ResolveAffectedProjects(repository, lookup);
  const vulnerability = createVulnerability({ id: 'CVE-2026-2000' });
  const graph: ComponentRelationshipGraph = {
    componentsByVulnerability: new Map([[
      'nvd::cve-2026-2000',
      [{
        evidence: 'purl',
        key: 'pkg:npm/legacy@1.0.0',
        name: 'legacy',
        vulnerabilityCount: 1
      }]
    ]]),
    relationships: [],
    vulnerabilitiesByComponent: new Map()
  };

  const result = await resolver.execute({
    componentIndex: {
      getSbomIdsForComponent: () => ['sbom-4']
    },
    relationships: graph,
    sboms: [{ id: 'sbom-4', label: 'Legacy Portal' }],
    vulnerabilities: [vulnerability]
  });

  assert.equal(result.get('nvd::cve-2026-2000')?.affectedProjects[0]?.status, 'broken');
});
