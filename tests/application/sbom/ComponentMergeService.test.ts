import assert from 'node:assert/strict';
import test from 'node:test';
import { ComponentMergeService } from '../../../src/application/sbom/ComponentMergeService';
import type { CatalogComponentInput } from '../../../src/application/sbom/types';
import type { NormalizedComponent } from '../../../src/domain/sbom/types';

const service = new ComponentMergeService();

const createComponent = (overrides: Partial<NormalizedComponent> = {}): NormalizedComponent => ({
  cweGroups: [],
  dataview: {
    cweList: [],
    severities: [],
    vulnerabilityCount: 0,
    vulnerabilityIds: []
  },
  id: 'component-1',
  name: 'lodash',
  vulnerabilities: [],
  vulnerabilityCount: 0,
  ...overrides
});

const createInput = (
  sourcePath: string,
  component: NormalizedComponent,
  format: 'cyclonedx' | 'spdx' = 'cyclonedx'
): CatalogComponentInput => ({
  component,
  document: {
    format,
    name: sourcePath.split('/').at(-1) ?? sourcePath,
    sourcePath
  }
});

test('merges source provenance and deduplicates vulnerabilities conservatively', () => {
  const left = service.createTrackedComponent('purl:pkg:npm/lodash@4.17.21', createInput(
    'reports/alpha.cdx.json',
    createComponent({
      highestSeverity: 'high',
      id: 'alpha-component',
      license: 'MIT',
      purl: 'pkg:npm/lodash@4.17.21',
      supplier: 'OpenJS',
      version: '4.17.21',
      vulnerabilities: [
        {
          cwes: [79],
          description: 'Short description',
          id: 'CVE-2026-0001',
          score: 7.5,
          severity: 'high'
        }
      ],
      vulnerabilityCount: 1
    })
  ));

  const right = service.createTrackedComponent('purl:pkg:npm/lodash@4.17.21', createInput(
    'reports/beta.spdx.json',
    createComponent({
      id: 'beta-component',
      license: 'MIT',
      purl: 'pkg:npm/lodash@4.17.21',
      version: '4.17.21',
      vulnerabilities: [
        {
          cwes: [79, 89],
          description: 'Longer description for the same vulnerability',
          id: 'CVE-2026-0001',
          score: 9.8,
          severity: 'critical'
        },
        {
          cwes: [22],
          id: 'CVE-2026-0002',
          score: 5.0,
          severity: 'medium'
        }
      ],
      vulnerabilityCount: 2
    }),
    'spdx'
  ));

  const merged = service.mergeComponents(left, right);

  assert.deepEqual(merged.sourceFiles, ['reports/alpha.cdx.json', 'reports/beta.spdx.json']);
  assert.deepEqual(merged.formats, ['cyclonedx', 'spdx']);
  assert.equal(merged.vulnerabilityCount, 2);
  assert.equal(merged.highestSeverity, 'critical');
  assert.equal(merged.sources.length, 2);
  assert.deepEqual(
    merged.vulnerabilities.map((vulnerability) => vulnerability.id),
    ['CVE-2026-0001', 'CVE-2026-0002']
  );
  assert.deepEqual(merged.vulnerabilities[0]?.cwes, [79, 89]);
  assert.equal(merged.vulnerabilities[0]?.score, 9.8);
  assert.equal(merged.vulnerabilities[0]?.description, 'Longer description for the same vulnerability');
  assert.deepEqual(merged.cweGroups, [
    {
      count: 1,
      cwe: 22,
      vulnerabilityIds: ['CVE-2026-0002']
    },
    {
      count: 1,
      cwe: 79,
      vulnerabilityIds: ['CVE-2026-0001']
    },
    {
      count: 1,
      cwe: 89,
      vulnerabilityIds: ['CVE-2026-0001']
    }
  ]);
});
