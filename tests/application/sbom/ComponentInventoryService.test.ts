import assert from 'node:assert/strict';
import test from 'node:test';
import { ComponentInventoryService } from '../../../src/application/sbom/ComponentInventoryService';
import { DEFAULT_SETTINGS } from '../../../src/application/use-cases/DefaultSettings';
import type { SbomLoadResult } from '../../../src/application/use-cases/SbomImportService';
import type { ImportedSbomConfig, VulnDashSettings } from '../../../src/application/use-cases/types';
import type { NormalizedSbomDocument } from '../../../src/domain/sbom/types';

const service = new ComponentInventoryService();

const createSbom = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: 'sbom-1',
  label: 'Primary SBOM',
  lastImportedAt: 0,
  path: 'reports/primary.cdx.json',
  ...overrides
});

const createDocument = (sourcePath: string): NormalizedSbomDocument => ({
  components: [
    {
      cweGroups: [{ count: 1, cwe: 79, vulnerabilityIds: ['CVE-2026-0001'] }],
      highestSeverity: 'high',
      id: 'component-1',
      license: 'MIT',
      name: 'lodash',
      purl: 'pkg:npm/lodash@4.17.21',
      supplier: 'Example Co',
      version: '4.17.21',
      vulnerabilities: [
        {
          cwes: [79],
          id: 'CVE-2026-0001',
          severity: 'high'
        }
      ],
      vulnerabilityCount: 1,
      vulnerabilitySummary: {
        cweIds: [79],
        highestSeverity: 'high',
        severities: ['high'],
        vulnerabilityCount: 1,
        vulnerabilityIds: ['CVE-2026-0001']
      },
    }
  ],
  format: 'cyclonedx',
  name: 'primary',
  sourcePath
});

const createSettings = (overrides: Partial<VulnDashSettings> = {}): VulnDashSettings => ({
  ...DEFAULT_SETTINGS,
  sboms: [createSbom()],
  ...overrides
});

test('buildSnapshot merges catalog data and applies follow/enable preferences', () => {
  const settings = createSettings({
    disabledSbomComponentKeys: ['purl:pkg:npm/lodash@4.17.21'],
    followedSbomComponentKeys: ['PURL:PKG:NPM/LODASH@4.17.21']
  });
  const results: SbomLoadResult[] = [{
    fromCache: false,
    sbomId: 'sbom-1',
    state: {
      components: [],
      document: createDocument('reports/primary.cdx.json'),
      hash: 'hash',
      lastError: null,
      lastLoadedAt: 0,
      sourcePath: 'reports/primary.cdx.json'
    },
    success: true
  }];

  const snapshot = service.buildSnapshot(settings, results);

  assert.equal(snapshot.catalog.componentCount, 1);
  assert.equal(snapshot.catalog.components[0]?.isFollowed, true);
  assert.equal(snapshot.catalog.components[0]?.isEnabled, false);
  assert.equal(snapshot.parsedSbomCount, 1);
  assert.equal(snapshot.failedSbomCount, 0);
});

test('buildSnapshot surfaces parse failures while preserving cached data context', () => {
  const settings = createSettings({
    sboms: [
      createSbom(),
      createSbom({
        id: 'sbom-2',
        label: 'Fallback SBOM',
        path: 'reports/fallback.spdx.json'
      })
    ]
  });
  const results: SbomLoadResult[] = [
    {
      fromCache: false,
      sbomId: 'sbom-1',
      state: {
        components: [],
        document: createDocument('reports/primary.cdx.json'),
        hash: 'hash',
        lastError: null,
        lastLoadedAt: 0,
        sourcePath: 'reports/primary.cdx.json'
      },
      success: true
    },
    {
      cachedState: {
        components: [],
        document: createDocument('reports/fallback.spdx.json'),
        hash: 'cached-hash',
        lastError: null,
        lastLoadedAt: 0,
        sourcePath: 'reports/fallback.spdx.json'
      },
      error: 'Unexpected token',
      sbomId: 'sbom-2',
      success: false
    }
  ];

  const snapshot = service.buildSnapshot(settings, results);

  assert.equal(snapshot.catalog.componentCount, 1);
  assert.equal(snapshot.failedSbomCount, 1);
  assert.equal(snapshot.parsedSbomCount, 2);
  assert.deepEqual(snapshot.issues, [{
    hasCachedData: true,
    message: 'Unexpected token',
    sbomId: 'sbom-2',
    sourcePath: 'reports/fallback.spdx.json',
    title: 'Fallback SBOM'
  }]);
});
