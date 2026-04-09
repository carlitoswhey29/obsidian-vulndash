import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomFilterMergeService } from '../../../src/application/services/SbomFilterMergeService';
import type { ImportedSbomConfig, RuntimeSbomState, VulnDashSettings } from '../../../src/application/services/types';
import { buildSbomOverrideKey } from '../../../src/application/services/types';

const mergeService = new SbomFilterMergeService();
const DEFAULT_SETTINGS: VulnDashSettings = {
  pollingIntervalMs: 60_000,
  pollOnStartup: true,
  keywordFilters: [],
  manualProductFilters: [],
  productFilters: [],
  minSeverity: 'MEDIUM',
  minCvssScore: 4,
  nvdApiKey: '',
  githubToken: '',
  systemNotificationsEnabled: true,
  desktopAlertsHighOrCritical: false,
  cacheDurationMs: 60_000,
  maxResults: 200,
  defaultSortOrder: 'publishedAt',
  colorCodedSeverity: true,
  columnVisibility: {
    id: true,
    title: true,
    source: true,
    severity: true,
    cvssScore: true,
    publishedAt: true
  },
  keywordRegexEnabled: false,
  enableNvdFeed: true,
  enableGithubFeed: true,
  autoNoteCreationEnabled: false,
  autoHighNoteCreationEnabled: false,
  autoNoteFolder: 'VulnDash Alerts',
  sboms: [],
  sbomOverrides: {},
  sbomImportMode: 'append',
  sbomPath: '',
  syncControls: {
    maxPages: 10,
    maxItems: 500,
    retryCount: 3,
    backoffBaseMs: 1000,
    overlapWindowMs: 180000,
    bootstrapLookbackMs: 86400000,
    debugHttpMetadata: false
  },
  sourceSyncCursor: {},
  settingsVersion: 4,
  feeds: []
};

const createSbom = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  contentHash: 'hash-1',
  enabled: true,
  id: 'sbom-1',
  label: 'Primary SBOM',
  lastImportedAt: 1,
  path: 'reports/sbom.json',
  ...overrides
});

const createRuntimeState = (names: Array<{ normalizedName: string; originalName: string }>): RuntimeSbomState => ({
  components: names,
  hash: 'hash-1',
  lastError: null,
  lastLoadedAt: 1,
  sourcePath: 'reports/sbom.json'
});

const createSettings = (overrides: Partial<VulnDashSettings> = {}): VulnDashSettings => ({
  ...DEFAULT_SETTINGS,
  ...overrides
});

test('append mode keeps manual filters and adds enabled SBOM components', () => {
  const filters = mergeService.merge(createSettings({
    manualProductFilters: ['Acme Portal'],
    sbomImportMode: 'append',
    sboms: [createSbom()]
  }), new Map([
    ['sbom-1', createRuntimeState([
      { normalizedName: 'Platform Api', originalName: 'platform-api' },
      { normalizedName: 'Portal Web', originalName: 'portal-web' }
    ])]
  ]));

  assert.deepEqual(filters, ['Acme Portal', 'Platform Api', 'Portal Web']);
});

test('replace mode uses SBOM components only and honors exclusions and overrides', () => {
  const settings = createSettings({
    manualProductFilters: ['Manual Filter'],
    sbomImportMode: 'replace',
    sbomOverrides: {
      [buildSbomOverrideKey('sbom-1', 'platform-api')]: { editedName: 'Platform Control Plane' },
      [buildSbomOverrideKey('sbom-1', 'portal-web')]: { excluded: true }
    },
    sboms: [createSbom()]
  });
  const filters = mergeService.merge(settings, new Map([
    ['sbom-1', createRuntimeState([
      { normalizedName: 'Platform Api', originalName: 'platform-api' },
      { normalizedName: 'Portal Web', originalName: 'portal-web' }
    ])]
  ]));

  assert.deepEqual(filters, ['Platform Control Plane']);
});

test('resolved components expose effective names without mutating runtime data', () => {
  const sbom = createSbom();
  const runtimeState = createRuntimeState([
    { normalizedName: 'Platform Api', originalName: 'platform-api' }
  ]);
  const resolved = mergeService.getResolvedComponents(sbom, runtimeState, {
    [buildSbomOverrideKey('sbom-1', 'platform-api')]: {
      editedName: 'Platform Control Plane',
      excluded: true
    }
  });

  assert.deepEqual(resolved, [{
    displayName: 'Platform Control Plane',
    editedName: 'Platform Control Plane',
    excluded: true,
    normalizedName: 'Platform Api',
    originalName: 'platform-api'
  }]);
  assert.equal(runtimeState.components[0]?.normalizedName, 'Platform Api');
});
