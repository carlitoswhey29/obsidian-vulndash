import assert from 'node:assert/strict';
import test from 'node:test';
import { buildTriageCorrelationKey, buildTriageCorrelationKeyForVulnerability, resolveTriageIdentity } from '../../../src/domain/triage/TriageCorrelation';

test('triage correlation keys normalize source and vulnerability identity deterministically', () => {
  const correlationKey = buildTriageCorrelationKey({
    source: '  GitHub  ',
    vulnerabilityId: ' GHSA-ABCD-1234 '
  });

  assert.equal(correlationKey, 'github::ghsa-abcd-1234');
});

test('triage correlation falls back to metadata identifiers when direct id is unavailable', () => {
  const identity = resolveTriageIdentity({
    metadata: {
      aliases: ['CVE-2026-9999']
    },
    source: 'nvd',
    vulnerabilityId: ' '
  });

  assert.equal(identity, 'cve-2026-9999');
});

test('triage correlation for vulnerabilities uses the stable source plus vulnerability id', () => {
  const correlationKey = buildTriageCorrelationKeyForVulnerability({
    id: 'CVE-2026-0001',
    metadata: {
      cveId: 'CVE-2026-0001',
      ghsaId: 'GHSA-1234'
    },
    source: 'NVD'
  });

  assert.equal(correlationKey, 'nvd::cve-2026-0001');
});
