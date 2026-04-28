import assert from 'node:assert/strict';
import test from 'node:test';
import type { VulnerabilityQuery } from '../../../src/application/query/QueryTypes';
import type { AffectedProjectResolution } from '../../../src/domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { VulnQueryEngine } from '../../../src/application/query/VulnQueryEngine';

const createVulnerability = (input: Partial<Vulnerability> & Pick<Vulnerability, 'id'>): Vulnerability => ({
  affectedProducts: input.affectedProducts ?? ['demo'],
  cvssScore: input.cvssScore ?? 5,
  id: input.id,
  publishedAt: input.publishedAt ?? '2026-04-01T00:00:00.000Z',
  references: input.references ?? [],
  severity: input.severity ?? 'MEDIUM',
  source: input.source ?? 'NVD',
  summary: input.summary ?? `${input.id} summary`,
  title: input.title ?? input.id,
  updatedAt: input.updatedAt ?? '2026-04-01T00:00:00.000Z',
  ...(input.metadata ? { metadata: input.metadata } : {})
});

const createResolution = (
  input: Partial<AffectedProjectResolution> = {}
): AffectedProjectResolution => ({
  affectedProjects: input.affectedProjects ?? [],
  unmappedSboms: input.unmappedSboms ?? []
});

const executeQuery = (
  vulnerabilities: readonly Vulnerability[],
  resolutions?: ReadonlyMap<string, AffectedProjectResolution>,
  overrides: Partial<VulnerabilityQuery> = {}
): Vulnerability[] => {
  const engine = new VulnQueryEngine();
  return engine.execute({
    getAffectedProjectResolution: (vulnerability) => resolutions?.get(vulnerability.id) ?? createResolution(),
    vulnerabilities
  }, {
    sort: {
      direction: 'desc',
      field: 'publishedAt'
    },
    ...overrides
  });
};

test('search filters by title, id, and source through the query engine', () => {
  const vulnerabilities = [
    createVulnerability({ id: 'CVE-2026-0001', title: 'Critical auth bypass', source: 'NVD' }),
    createVulnerability({ id: 'GHSA-2026-0002', title: 'Dependency issue', source: 'GitHub' }),
    createVulnerability({ id: 'OSV-2026-0003', title: 'Parser crash', source: 'OSV' })
  ];

  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, { searchText: 'github' }).map((item) => item.id),
    ['GHSA-2026-0002']
  );
  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, { searchText: 'auth' }).map((item) => item.id),
    ['CVE-2026-0001']
  );
  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, { searchText: '2026-0003' }).map((item) => item.id),
    ['OSV-2026-0003']
  );
});

test('sorting is executed by the query engine for the requested field and direction', () => {
  const vulnerabilities = [
    createVulnerability({ id: 'CVE-2026-0001', cvssScore: 5.1 }),
    createVulnerability({ id: 'CVE-2026-0002', cvssScore: 9.8 }),
    createVulnerability({ id: 'CVE-2026-0003', cvssScore: 7.4 })
  ];

  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, {
      sort: {
        direction: 'asc',
        field: 'cvssScore'
      }
    }).map((item) => item.id),
    ['CVE-2026-0001', 'CVE-2026-0003', 'CVE-2026-0002']
  );
});

test('date filtering uses the requested dashboard date field and range', () => {
  const vulnerabilities = [
    createVulnerability({
      id: 'CVE-2026-0001',
      publishedAt: '2026-04-22T12:00:00.000Z',
      updatedAt: '2026-04-10T12:00:00.000Z'
    }),
    createVulnerability({
      id: 'CVE-2026-0002',
      publishedAt: '2026-04-10T12:00:00.000Z',
      updatedAt: '2026-04-22T12:00:00.000Z'
    })
  ];

  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, {
      date: {
        field: 'published',
        now: new Date('2026-04-23T00:00:00.000Z'),
        range: { preset: 'past_day' }
      }
    }).map((item) => item.id),
    ['CVE-2026-0001']
  );
  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, {
      date: {
        field: 'modified',
        now: new Date('2026-04-23T00:00:00.000Z'),
        range: { preset: 'past_day' }
      }
    }).map((item) => item.id),
    ['CVE-2026-0002']
  );
});

test('severity filtering is owned by the query engine', () => {
  const vulnerabilities = [
    createVulnerability({ id: 'CVE-2026-0001', severity: 'LOW' }),
    createVulnerability({ id: 'CVE-2026-0002', severity: 'CRITICAL' }),
    createVulnerability({ id: 'CVE-2026-0003', severity: 'HIGH' })
  ];

  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, {
      severities: ['CRITICAL', 'HIGH']
    }).map((item) => item.id),
    ['CVE-2026-0003', 'CVE-2026-0002']
  );
});

test('compound filters combine project, severity, date, search, sort, and limit', () => {
  const vulnerabilities = [
    createVulnerability({
      id: 'CVE-2026-0001',
      publishedAt: '2026-04-22T05:00:00.000Z',
      severity: 'CRITICAL',
      title: 'Portal auth bypass'
    }),
    createVulnerability({
      id: 'CVE-2026-0002',
      publishedAt: '2026-04-22T06:00:00.000Z',
      severity: 'HIGH',
      title: 'Portal config exposure'
    }),
    createVulnerability({
      id: 'CVE-2026-0003',
      publishedAt: '2026-04-22T07:00:00.000Z',
      severity: 'CRITICAL',
      title: 'Gateway auth bypass'
    })
  ];
  const resolutions = new Map<string, AffectedProjectResolution>([
    ['CVE-2026-0001', createResolution({
      affectedProjects: [{
        displayName: 'Portal',
        notePath: 'Projects/Portal.md',
        sourceSbomIds: ['sbom-1'],
        sourceSbomLabels: ['Portal SBOM'],
        status: 'linked'
      }]
    })],
    ['CVE-2026-0002', createResolution({
      affectedProjects: [{
        displayName: 'Portal',
        notePath: 'Projects/Portal.md',
        sourceSbomIds: ['sbom-2'],
        sourceSbomLabels: ['Portal SBOM'],
        status: 'linked'
      }]
    })],
    ['CVE-2026-0003', createResolution({
      affectedProjects: [{
        displayName: 'Gateway',
        notePath: 'Projects/Gateway.md',
        sourceSbomIds: ['sbom-3'],
        sourceSbomLabels: ['Gateway SBOM'],
        status: 'linked'
      }]
    })]
  ]);

  assert.deepEqual(
    executeQuery(vulnerabilities, resolutions, {
      affectedProject: {
        kind: 'project',
        notePath: 'Projects/Portal.md'
      },
      date: {
        field: 'published',
        now: new Date('2026-04-23T00:00:00.000Z'),
        range: { preset: 'past_day' }
      },
      limit: 1,
      searchText: 'portal',
      severities: ['CRITICAL', 'HIGH'],
      sort: {
        direction: 'desc',
        field: 'severity'
      }
    }).map((item) => item.id),
    ['CVE-2026-0001']
  );
});

test('empty results are returned when no vulnerabilities match the compound query', () => {
  const vulnerabilities = [
    createVulnerability({ id: 'CVE-2026-0001', severity: 'LOW', title: 'Portal cache issue' })
  ];

  assert.deepEqual(
    executeQuery(vulnerabilities, undefined, {
      searchText: 'auth',
      severities: ['CRITICAL']
    }),
    []
  );
});
