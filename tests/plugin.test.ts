import assert from 'node:assert/strict';
import test from 'node:test';
import { BUILT_IN_FEEDS, FEED_TYPES } from '../src/domain/feeds/FeedTypes';
import { buildPersistedSettingsSnapshot } from '../src/application/settings/SettingsMigrator';
import { DEFAULT_SETTINGS, SETTINGS_VERSION } from '../src/application/use-cases/DefaultSettings';

test('buildPersistedSettingsSnapshot keeps persisted SBOM settings lean and normalized', () => {
  const snapshot = buildPersistedSettingsSnapshot({
    ...DEFAULT_SETTINGS,
    dailyRollup: {
      ...DEFAULT_SETTINGS.dailyRollup,
      folderPath: 'briefings/daily'
    },
    manualProductFilters: ['Portal Web'],
    sbomFolders: ['reports', ' reports ', '', 'reports/nested'],
    followedSbomComponentKeys: ['PURL:PKG:NPM/LODASH@4.17.21', 'purl:pkg:npm/lodash@4.17.21'],
    disabledSbomComponentKeys: [' name-version:legacy@1.0.0 ', 'name-version:legacy@1.0.0'],
    productFilters: ['Portal Web', 'Gateway Service'],
    sbomOverrides: {
      'sbom-1::portal-web': { editedName: 'Portal Web' },
      'sbom-1::gateway': {}
    },
    sbomPath: 'legacy/path.json'
  }, {
    githubToken: 'encrypted-github',
    nvdApiKey: 'encrypted-nvd'
  }, DEFAULT_SETTINGS.feeds.map((feed) => ({ ...feed })));

  assert.equal(snapshot.sbomPath, '');
  assert.equal(snapshot.settingsVersion, SETTINGS_VERSION);
  assert.equal(snapshot.nvdApiKey, 'encrypted-nvd');
  assert.equal(snapshot.githubToken, 'encrypted-github');
  assert.equal(snapshot.dailyRollup.folderPath, 'briefings/daily');
  assert.deepEqual(snapshot.sbomFolders, ['reports', 'reports/nested']);
  assert.deepEqual(snapshot.followedSbomComponentKeys, ['purl:pkg:npm/lodash@4.17.21']);
  assert.deepEqual(snapshot.disabledSbomComponentKeys, ['name-version:legacy@1.0.0']);
  assert.deepEqual(snapshot.sbomOverrides, {
    'sbom-1::portal-web': { editedName: 'Portal Web' }
  });
  assert.deepEqual(snapshot.manualProductFilters, ['Portal Web']);
  assert.deepEqual(snapshot.productFilters, ['Portal Web', 'Gateway Service']);
});

test('default settings include a safe OSV feed configuration', () => {
  const osvFeed = DEFAULT_SETTINGS.feeds.find((feed) => feed.type === FEED_TYPES.OSV);

  assert.ok(osvFeed);
  assert.equal(osvFeed?.id, BUILT_IN_FEEDS.OSV.id);
  assert.equal(osvFeed?.enabled, false);
  assert.equal(osvFeed?.cacheTtlMs, 21_600_000);
  assert.equal(osvFeed?.negativeCacheTtlMs, 3_600_000);
  assert.equal(osvFeed?.requestTimeoutMs, 15_000);
  assert.equal(osvFeed?.maxConcurrentBatches, 4);
});
