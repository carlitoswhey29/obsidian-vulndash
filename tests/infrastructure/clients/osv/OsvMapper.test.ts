import assert from 'node:assert/strict';
import test from 'node:test';
import { OsvMapper } from '../../../../src/infrastructure/clients/osv/OsvMapper';

test('OSV mapper prefers parseable CVSS severity over weaker fallbacks', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-1000',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Critical parser flaw',
    severity: [
      {
        type: 'CVSS_V3',
        score: '9.8'
      }
    ],
    database_specific: {
      severity: 'low'
    }
  });

  assert.equal(vulnerability.id, 'OSV-2026-1000');
  assert.equal(vulnerability.cvssScore, 9.8);
  assert.equal(vulnerability.severity, 'CRITICAL');
});

test('OSV mapper normalizes severity aliases and preserves package metadata without throwing on sparse payloads', () => {
  const mapper = new OsvMapper('OSV');

  const vulnerability = mapper.normalize({
    id: 'OSV-2026-2000',
    modified: '2026-04-22T00:00:00.000Z',
    summary: 'Moderate issue',
    database_specific: {
      severity: 'moderate',
      source: 'https://github.com/example/advisory'
    },
    aliases: ['CVE-2026-2000'],
    affected: [
      {
        package: {
          ecosystem: 'npm',
          name: '@example/widget',
          purl: 'PKG:NPM/%40EXAMPLE/WIDGET@1.2.3'
        },
        ranges: [
          {
            type: 'ECOSYSTEM',
            events: [
              { introduced: '0' },
              { fixed: '1.2.4' }
            ]
          }
        ]
      }
    ]
  });

  assert.equal(vulnerability.severity, 'MEDIUM');
  assert.equal(vulnerability.metadata?.cveId, 'CVE-2026-2000');
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.purl, 'pkg:npm/@example/widget@1.2.3');
  assert.equal(vulnerability.metadata?.affectedPackages?.[0]?.version, '1.2.3');
  assert.equal(vulnerability.metadata?.vulnerableVersionRanges?.[0], '@example/widget: < 1.2.4');
  assert.ok(vulnerability.references.includes('https://github.com/example/advisory'));
});
