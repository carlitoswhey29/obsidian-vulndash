import assert from 'node:assert/strict';
import test from 'node:test';
import type { ImportedSbomConfig } from '../../../src/application/use-cases/types';
import {
  describeSbomFileStatus,
  filterSbomComparisonResult,
  sortSbomFileCandidates,
  summarizeSbomWorkspace
} from '../../../src/application/use-cases/SbomWorkspaceService';

const createSbom = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: 'sbom-1',
  label: 'Primary SBOM',
  lastImportedAt: 0,
  path: 'reports/sbom.json',
  ...overrides
});

test('prioritizes likely SBOM JSON files for the vault picker', () => {
  const files = sortSbomFileCandidates([
    { path: 'docs/readme.md' },
    { path: 'reports/cyclonedx.json' },
    { path: 'inventory/components.json' },
    { path: 'exports/sbom-app.json' },
    { path: 'data/notes.json' }
  ]);

  assert.deepEqual(files.map((file) => file.path), [
    'exports/sbom-app.json',
    'reports/cyclonedx.json',
    'inventory/components.json',
    'data/notes.json'
  ]);
});

test('summarizes enabled, changed, and error SBOM counts for the workspace', () => {
  const summary = summarizeSbomWorkspace([
    createSbom(),
    createSbom({ enabled: false, id: 'sbom-2', lastError: 'Parse failure' }),
    createSbom({ id: 'sbom-3' })
  ], new Map([
    ['sbom-1', { currentHash: 'hash-1', error: null, status: 'unchanged' }],
    ['sbom-2', { currentHash: null, error: 'Missing', status: 'missing' }],
    ['sbom-3', { currentHash: 'hash-3', error: null, status: 'changed' }]
  ]));

  assert.deepEqual(summary, {
    changed: 1,
    configured: 3,
    enabled: 2,
    withErrors: 1
  });
});

test('filters comparison results in memory without changing the underlying groups', () => {
  const filtered = filterSbomComparisonResult({
    inBoth: ['Platform Api', 'Portal Web'],
    onlyInA: ['Billing Worker'],
    onlyInB: ['Gateway Service']
  }, 'plat');

  assert.deepEqual(filtered, {
    inBoth: ['Platform Api'],
    onlyInA: [],
    onlyInB: []
  });
});

test('maps file change states to user-facing badge copy', () => {
  assert.deepEqual(
    describeSbomFileStatus({ currentHash: 'hash', error: null, status: 'changed' }),
    { label: 'Changed since last sync', tone: 'warning' }
  );
  assert.deepEqual(
    describeSbomFileStatus({ currentHash: null, error: 'ENOENT', status: 'error' }),
    { label: 'ENOENT', tone: 'danger' }
  );
});
