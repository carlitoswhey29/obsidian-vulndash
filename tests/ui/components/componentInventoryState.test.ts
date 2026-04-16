import assert from 'node:assert/strict';
import test from 'node:test';
import type { ComponentInventorySnapshot, TrackedComponent } from '../../../src/application/sbom/types';
import {
  createDefaultComponentInventoryFilters,
  deriveComponentInventoryState,
  filterTrackedComponents
} from '../../../src/ui/components/componentInventoryState';

const createComponent = (overrides: Partial<TrackedComponent> = {}): TrackedComponent => ({
  cweGroups: [],
  formats: ['cyclonedx'],
  isEnabled: true,
  isFollowed: false,
  key: 'name-version:component@1.0.0',
  name: 'component',
  sourceFiles: ['reports/a.cdx.json'],
  sources: [{
    componentId: 'component-1',
    documentName: 'a',
    format: 'cyclonedx',
    name: 'component',
    sourcePath: 'reports/a.cdx.json',
    version: '1.0.0'
  }],
  vulnerabilities: [],
  vulnerabilityCount: 0,
  version: '1.0.0',
  ...overrides
});

const createSnapshot = (components: TrackedComponent[]): ComponentInventorySnapshot => ({
  catalog: {
    componentCount: components.length,
    components,
    formats: ['cyclonedx', 'spdx'],
    sourceFiles: ['reports/a.cdx.json', 'reports/b.spdx.json']
  },
  configuredSbomCount: 2,
  enabledSbomCount: 2,
  failedSbomCount: 0,
  issues: [],
  parsedSbomCount: 2
});

test('filterTrackedComponents combines search, follow, enabled, vulnerability, severity, format, and source filters', () => {
  const components = [
    createComponent({
      cweGroups: [{ count: 1, cwe: 79, vulnerabilityIds: ['CVE-2026-0001'] }],
      highestSeverity: 'high',
      isFollowed: true,
      key: 'purl:pkg:npm/lodash@4.17.21',
      name: 'lodash',
      purl: 'pkg:npm/lodash@4.17.21',
      supplier: 'Example Co',
      vulnerabilities: [{
        cwes: [79],
        id: 'CVE-2026-0001',
        severity: 'high'
      }],
      vulnerabilityCount: 1,
      version: '4.17.21'
    }),
    createComponent({
      formats: ['spdx'],
      isEnabled: false,
      key: 'name-version:express@4.19.2',
      name: 'express',
      sourceFiles: ['reports/b.spdx.json'],
      sources: [{
        componentId: 'component-2',
        documentName: 'b',
        format: 'spdx',
        name: 'express',
        sourcePath: 'reports/b.spdx.json',
        version: '4.19.2'
      }],
      version: '4.19.2'
    })
  ];

  const filters = {
    ...createDefaultComponentInventoryFilters(),
    enabledOnly: true,
    followedOnly: true,
    searchQuery: 'lodash cve-2026-0001',
    severityThreshold: 'medium' as const,
    sourceFile: 'reports/a.cdx.json',
    sourceFormat: 'cyclonedx' as const,
    vulnerableOnly: true
  };

  assert.deepEqual(filterTrackedComponents(components, filters).map((component) => component.name), ['lodash']);
});

test('deriveComponentInventoryState returns deterministic summaries and no-results visibility data', () => {
  const snapshot = createSnapshot([
    createComponent({
      isFollowed: true,
      key: 'purl:pkg:npm/lodash@4.17.21',
      name: 'lodash',
      vulnerabilities: [{
        cwes: [79],
        id: 'CVE-2026-0001',
        severity: 'high'
      }],
      vulnerabilityCount: 1
    }),
    createComponent({
      isEnabled: false,
      key: 'name-version:express@4.19.2',
      name: 'express'
    })
  ]);

  const derived = deriveComponentInventoryState(snapshot, {
    ...createDefaultComponentInventoryFilters(),
    followedOnly: true
  });

  assert.equal(derived.summary.totalCount, 2);
  assert.equal(derived.summary.followedCount, 1);
  assert.equal(derived.summary.enabledCount, 1);
  assert.equal(derived.summary.vulnerableCount, 1);
  assert.equal(derived.hasActiveFilters, true);
  assert.deepEqual(derived.components.map((component) => component.name), ['lodash']);
  assert.deepEqual(derived.availableSourceFiles, ['reports/a.cdx.json', 'reports/b.spdx.json']);
});
