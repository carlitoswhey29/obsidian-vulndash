import test from 'node:test';
import assert from 'node:assert/strict';
import { NvdMapper } from '../../../../src/infrastructure/clients/nvd/NvdMapper';

test('uses CVSS v3.0 when v3.1 is absent', () => {
  const mapper = new NvdMapper('NVD');
  const vulnerability = mapper.normalize({
    id: 'CVE-2026-6000',
    published: '2026-04-15T00:00:00.000Z',
    lastModified: '2026-04-15T01:00:00.000Z',
    descriptions: [{ lang: 'en', value: 'A high severity issue in the parser.' }],
    metrics: {
      cvssMetricV30: [{ cvssData: { baseScore: 7.4 } }]
    }
  });

  assert.equal(vulnerability.cvssScore, 7.4);
  assert.equal(vulnerability.severity, 'HIGH');
});

test('falls back to CVSS v2 when newer scores are unavailable', () => {
  const mapper = new NvdMapper('NVD');
  const vulnerability = mapper.normalize({
    id: 'CVE-2026-6001',
    published: '2026-04-15T00:00:00.000Z',
    lastModified: '2026-04-15T01:00:00.000Z',
    descriptions: [{ lang: 'en', value: 'Legacy vulnerability data.' }],
    metrics: {
      cvssMetricV2: [{ cvssData: { baseScore: 4.3 } }]
    }
  });

  assert.equal(vulnerability.cvssScore, 4.3);
  assert.equal(vulnerability.severity, 'MEDIUM');
});

test('extracts CWE and affected package metadata from NVD records', () => {
  const mapper = new NvdMapper('NVD');
  const vulnerability = mapper.normalize({
    id: 'CVE-2026-6002',
    published: '2026-04-15T00:00:00.000Z',
    lastModified: '2026-04-15T01:00:00.000Z',
    descriptions: [{ lang: 'en', value: 'Acme Widget allows remote code execution.' }],
    references: [{ url: 'https://example.com/CVE-2026-6002' }],
    weaknesses: [{
      description: [
        { lang: 'en', value: 'CWE-78' },
        { lang: 'en', value: 'NVD-CWE-noinfo' }
      ]
    }],
    configurations: [{
      nodes: [{
        cpeMatch: [{
          vulnerable: true,
          criteria: 'cpe:2.3:a:acme:widget:2.3.4:*:*:*:*:*:*:*',
          versionStartIncluding: '2.0.0',
          versionEndExcluding: '2.4.0'
        }]
      }]
    }]
  });

  assert.deepEqual(vulnerability.metadata?.cwes, ['CWE-78']);
  assert.deepEqual(vulnerability.metadata?.vendors, ['Acme']);
  assert.deepEqual(vulnerability.metadata?.packages, ['Widget']);
  assert.deepEqual(vulnerability.metadata?.affectedPackages, [{
    cpe: 'cpe:2.3:a:acme:widget:2.3.4:*:*:*:*:*:*:*',
    name: 'Widget',
    vendor: 'Acme',
    version: '2.3.4',
    vulnerableVersionRange: '2.3.4, >= 2.0.0, < 2.4.0'
  }]);
  assert.deepEqual(vulnerability.metadata?.vulnerableVersionRanges, ['Acme Widget: 2.3.4, >= 2.0.0, < 2.4.0']);
  assert.equal(vulnerability.metadata?.sourceUrls?.html, 'https://nvd.nist.gov/vuln/detail/CVE-2026-6002');
  assert.ok(vulnerability.references.includes('https://example.com/CVE-2026-6002'));
});
