import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomComponentIndex } from '../../../src/infrastructure/correlation/SbomComponentIndex';
import type { TrackedComponent } from '../../../src/application/sbom/types';

const createComponent = (key: string, sourcePaths: string[]): TrackedComponent => ({
  cweGroups: [],
  formats: ['cyclonedx'],
  isEnabled: true,
  isFollowed: false,
  key,
  name: key,
  sourceFiles: sourcePaths,
  sources: sourcePaths.map((sourcePath, index) => ({
    componentId: `component-${index}`,
    documentName: 'demo',
    format: 'cyclonedx',
    name: key,
    sourcePath
  })),
  vulnerabilities: [],
  vulnerabilityCount: 0
});

test('SbomComponentIndex deduplicates sbom ids across shared component sources', () => {
  const index = new SbomComponentIndex().build([
    createComponent('pkg:npm/portal@1.0.0', ['reports/portal.json', 'reports/gateway.json'])
  ], new Map([
    ['reports/portal.json', ['sbom-1', 'sbom-2']],
    ['reports/gateway.json', ['sbom-2', 'sbom-3']]
  ]));

  assert.deepEqual(index.getSbomIdsForComponent('PKG:NPM/PORTAL@1.0.0'), ['sbom-1', 'sbom-2', 'sbom-3']);
});
