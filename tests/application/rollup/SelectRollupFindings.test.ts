import assert from 'node:assert/strict';
import test from 'node:test';
import { SelectRollupFindings, type RollupTriageSnapshot } from '../../../src/application/rollup/SelectRollupFindings';
import { DailyRollupPolicy } from '../../../src/domain/rollup/DailyRollupPolicy';
import type { AffectedProjectResolution } from '../../../src/domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { TriageRecord } from '../../../src/domain/triage/TriageRecord';

const createVulnerability = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  affectedProducts: ['portal'],
  cvssScore: 8.5,
  id: 'CVE-2026-1000',
  publishedAt: '2026-04-18T00:00:00.000Z',
  references: [],
  severity: 'HIGH',
  source: 'NVD',
  summary: 'Portal issue',
  title: 'Portal vulnerability',
  updatedAt: '2026-04-18T06:00:00.000Z',
  ...overrides
});

const mappedResolution: AffectedProjectResolution = {
  affectedProjects: [{
    displayName: 'Portal Platform',
    notePath: 'Projects/Portal.md',
    sourceSbomIds: ['sbom-1'],
    sourceSbomLabels: ['Portal API'],
    status: 'linked'
  }],
  unmappedSboms: []
};

const unmappedResolution: AffectedProjectResolution = {
  affectedProjects: [],
  unmappedSboms: [{ sbomId: 'sbom-2', sbomLabel: 'Gateway SBOM' }]
};

test('SelectRollupFindings applies severity and triage policy to correlated findings', () => {
  const selector = new SelectRollupFindings();
  const vulnerabilities = [
    createVulnerability({ id: 'CVE-2026-1000', severity: 'CRITICAL' }),
    createVulnerability({ id: 'CVE-2026-1001', severity: 'HIGH' }),
    createVulnerability({ id: 'CVE-2026-1002', severity: 'MEDIUM' })
  ];
  const triageByCacheKey = new Map<string, RollupTriageSnapshot>([
    ['NVD:CVE-2026-1000', {
      record: TriageRecord.create({
        correlationKey: 'nvd::cve-2026-1000',
        source: 'NVD',
        state: 'active',
        updatedAt: '2026-04-18T10:00:00.000Z',
        vulnerabilityId: 'CVE-2026-1000'
      })
    }],
    ['NVD:CVE-2026-1001', {
      record: TriageRecord.create({
        correlationKey: 'nvd::cve-2026-1001',
        source: 'NVD',
        state: 'suppressed',
        updatedAt: '2026-04-18T10:05:00.000Z',
        vulnerabilityId: 'CVE-2026-1001'
      })
    }],
    ['NVD:CVE-2026-1002', {
      record: null
    }]
  ]);
  const affectedProjectsByVulnerabilityRef = new Map([
    ['nvd::cve-2026-1000', mappedResolution],
    ['nvd::cve-2026-1001', mappedResolution],
    ['nvd::cve-2026-1002', mappedResolution]
  ]);

  const findings = selector.execute({
    affectedProjectsByVulnerabilityRef,
    policy: new DailyRollupPolicy({
      excludedTriageStates: ['suppressed'],
      includeUnmappedFindings: false,
      severityThreshold: 'HIGH'
    }),
    triageByCacheKey,
    vulnerabilities
  });

  assert.deepEqual(findings.map((finding) => finding.vulnerability.id), ['CVE-2026-1000']);
  assert.equal(findings[0]?.triageState, 'active');
});

test('SelectRollupFindings can include unmapped findings and deduplicates repeated vulnerabilities', () => {
  const selector = new SelectRollupFindings();
  const vulnerability = createVulnerability({ id: 'CVE-2026-2000', source: 'GitHub', summary: 'Gateway issue' });

  const findings = selector.execute({
    affectedProjectsByVulnerabilityRef: new Map([
      ['github::cve-2026-2000', unmappedResolution]
    ]),
    policy: new DailyRollupPolicy({
      excludedTriageStates: [],
      includeUnmappedFindings: true,
      severityThreshold: 'HIGH'
    }),
    triageByCacheKey: new Map(),
    vulnerabilities: [vulnerability, { ...vulnerability }]
  });

  assert.equal(findings.length, 1);
  assert.deepEqual(findings[0]?.unmappedSboms, unmappedResolution.unmappedSboms);
});

test('SelectRollupFindings derives triage state from the record or the default state', () => {
  const selector = new SelectRollupFindings();
  const vulnerabilities = [
    createVulnerability({ id: 'CVE-2026-3000', source: 'GitHub', summary: 'First issue' }),
    createVulnerability({ id: 'CVE-2026-3001', source: 'GitHub', summary: 'Second issue' })
  ];

  const findings = selector.execute({
    affectedProjectsByVulnerabilityRef: new Map([
      ['github::cve-2026-3000', mappedResolution],
      ['github::cve-2026-3001', mappedResolution]
    ]),
    policy: new DailyRollupPolicy({
      excludedTriageStates: ['investigating'],
      includeUnmappedFindings: false,
      severityThreshold: 'HIGH'
    }),
    triageByCacheKey: new Map([
      ['GitHub:CVE-2026-3000', {
        record: TriageRecord.create({
          correlationKey: 'github::cve-2026-3000',
          source: 'GitHub',
          state: 'investigating',
          updatedAt: '2026-04-18T10:00:00.000Z',
          vulnerabilityId: 'CVE-2026-3000'
        })
      }],
      ['GitHub:CVE-2026-3001', {
        record: null
      }]
    ]),
    vulnerabilities
  });

  assert.deepEqual(findings.map((finding) => finding.vulnerability.id), ['CVE-2026-3001']);
  assert.equal(findings[0]?.triageState, 'active');
});
