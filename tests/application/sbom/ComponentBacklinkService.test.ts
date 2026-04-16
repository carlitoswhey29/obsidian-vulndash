import assert from 'node:assert/strict';
import test from 'node:test';
import { ComponentBacklinkService } from '../../../src/application/sbom/ComponentBacklinkService';
import type { ComponentRelationshipGraph } from '../../../src/application/sbom/types';

const service = new ComponentBacklinkService();

const createGraph = (): ComponentRelationshipGraph => ({
  componentsByVulnerability: new Map([[
    'github::ghsa-aaaa-bbbb-cccc',
    [
      {
        evidence: 'purl',
        key: 'purl:pkg:npm/lodash@4.17.21',
        name: 'lodash',
        notePath: 'Components/Lodash.md',
        purl: 'pkg:npm/lodash@4.17.21',
        version: '4.17.21',
        vulnerabilityCount: 1
      },
      {
        evidence: 'name-version',
        key: 'name-version:express@4.19.2',
        name: 'express',
        version: '4.19.2',
        vulnerabilityCount: 0
      }
    ]
  ]]),
  relationships: [],
  vulnerabilitiesByComponent: new Map()
});

test('builds deterministic vulnerability note relationship context', () => {
  const context = service.buildVulnerabilityNoteContext('github::ghsa-aaaa-bbbb-cccc', createGraph());

  assert.deepEqual(context.relatedComponentKeys, [
    'purl:pkg:npm/lodash@4.17.21',
    'name-version:express@4.19.2'
  ]);
  assert.deepEqual(context.relatedComponentNames, [
    'lodash 4.17.21',
    'express 4.19.2'
  ]);
  assert.deepEqual(context.relatedComponentNotePaths, ['Components/Lodash.md']);
  assert.deepEqual(context.relatedComponentSectionLines, [
    '- [[Components/Lodash.md|lodash 4.17.21]] (purl)',
    '- express 4.19.2 (name-version)'
  ]);
});

test('upsertRelatedVulnerabilitySection avoids duplicate links and preserves a stable managed section', () => {
  const existing = [
    '# Component Note',
    '',
    '<!-- vulndash:related-vulnerabilities:start -->',
    '## Related Vulnerabilities',
    '- [[VulnDash Alerts/CVE-2026-0001.md|CVE-2026-0001]]',
    '<!-- vulndash:related-vulnerabilities:end -->'
  ].join('\n');

  const updated = service.upsertRelatedVulnerabilitySection(existing, [
    { label: 'CVE-2026-0001', notePath: 'VulnDash Alerts/CVE-2026-0001.md' },
    { label: 'GHSA-aaaa-bbbb-cccc', notePath: 'VulnDash Alerts/GHSA-aaaa-bbbb-cccc.md' }
  ]);

  assert.equal(updated.match(/CVE-2026-0001/g)?.length, 2);
  assert.match(updated, /GHSA-aaaa-bbbb-cccc/);
  assert.equal(updated.match(/vulndash:related-vulnerabilities:start/g)?.length, 1);
  assert.equal(updated.match(/vulndash:related-vulnerabilities:end/g)?.length, 1);
});
