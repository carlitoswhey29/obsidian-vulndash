import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomFilterMergeService } from '../../../src/application/services/SbomFilterMergeService';
import type { ImportedSbomConfig, VulnDashSettings } from '../../../src/application/services/types';
import { DEFAULT_SETTINGS, migrateLegacySettings } from '../../../src/plugin';

const mergeService = new SbomFilterMergeService();

const createSbom = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  id: 'sbom-1',
  label: 'Primary SBOM',
  path: 'reports/sbom.json',
  namespace: '',
  enabled: true,
  components: [],
  lastImportedAt: null,
  lastImportHash: null,
  lastImportError: null,
  ...overrides
});

const createSettings = (overrides: Partial<VulnDashSettings> = {}): VulnDashSettings => ({
  ...DEFAULT_SETTINGS,
  ...overrides
});

test('append mode keeps manual filters and adds enabled imported components', () => {
  const filters = mergeService.merge(createSettings({
    manualProductFilters: ['Acme Portal'],
    sbomImportMode: 'append',
    sboms: [
      createSbom({
        components: [
          {
            id: 'component-1',
            name: 'platform-api',
            normalizedName: 'Platform Api',
            version: '1.0.0',
            purl: '',
            cpe: '',
            bomRef: '',
            namespace: '',
            enabled: true,
            excluded: false
          },
          {
            id: 'component-2',
            name: 'disabled-component',
            normalizedName: 'Disabled Component',
            version: '',
            purl: '',
            cpe: '',
            bomRef: '',
            namespace: '',
            enabled: false,
            excluded: false
          }
        ]
      })
    ]
  }));

  assert.deepEqual(filters, ['Acme Portal', 'Platform Api']);
});

test('replace mode ignores manual filters and honors exclusions and disabled SBOMs', () => {
  const filters = mergeService.merge(createSettings({
    manualProductFilters: ['Manual Filter'],
    sbomImportMode: 'replace',
    sboms: [
      createSbom({
        enabled: true,
        components: [{
          id: 'component-1',
          name: 'platform-api',
          normalizedName: 'Platform Api',
          version: '',
          purl: '',
          cpe: '',
          bomRef: '',
          namespace: '',
          enabled: true,
          excluded: true
        }]
      }),
      createSbom({
        id: 'sbom-2',
        enabled: false,
        components: [{
          id: 'component-2',
          name: 'portal-web',
          normalizedName: 'Portal Web',
          version: '',
          purl: '',
          cpe: '',
          bomRef: '',
          namespace: '',
          enabled: true,
          excluded: false
        }]
      })
    ]
  }));

  assert.deepEqual(filters, []);
});

test('auto apply disabled keeps only manual filters', () => {
  const filters = mergeService.merge(createSettings({
    manualProductFilters: ['Manual Filter'],
    sbomAutoApplyFilters: false,
    sbomImportMode: 'append',
    sboms: [
      createSbom({
        components: [{
          id: 'component-1',
          name: 'platform-api',
          normalizedName: 'Platform Api',
          version: '',
          purl: '',
          cpe: '',
          bomRef: '',
          namespace: '',
          enabled: true,
          excluded: false
        }]
      })
    ]
  }));

  assert.deepEqual(filters, ['Manual Filter']);
});

test('migrates legacy sbomPath into sboms and preserves manual filters separately', () => {
  const migrated = migrateLegacySettings({
    productFilters: ['Portal Web', 'Platform Api'],
    sbomPath: 'reports/sbom.json',
    settingsVersion: 2
  });

  assert.deepEqual(migrated.manualProductFilters, ['Portal Web', 'Platform Api']);
  assert.equal(migrated.productFilters.includes('Portal Web'), true);
  assert.equal(migrated.sboms.length, 1);
  assert.equal(migrated.sboms[0]?.path, 'reports/sbom.json');
  assert.equal(migrated.sbomPath, '');
});
