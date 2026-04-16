import assert from 'node:assert/strict';
import test from 'node:test';
import { buildPersistedSettingsSnapshot, DEFAULT_SETTINGS, migrateLegacySettings, SETTINGS_VERSION } from '../src/plugin';

test('buildPersistedSettingsSnapshot keeps persisted SBOM settings lean and normalized', () => {
  const snapshot = buildPersistedSettingsSnapshot({
    ...DEFAULT_SETTINGS,
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
  assert.deepEqual(snapshot.sbomFolders, ['reports', 'reports/nested']);
  assert.deepEqual(snapshot.followedSbomComponentKeys, ['purl:pkg:npm/lodash@4.17.21']);
  assert.deepEqual(snapshot.disabledSbomComponentKeys, ['name-version:legacy@1.0.0']);
  assert.deepEqual(snapshot.sbomOverrides, {
    'sbom-1::portal-web': { editedName: 'Portal Web' }
  });
  assert.deepEqual(snapshot.manualProductFilters, ['Portal Web']);
  assert.deepEqual(snapshot.productFilters, ['Portal Web', 'Gateway Service']);
});

test('migrateLegacySettings defaults malformed component preference arrays safely', () => {
  const migrated = migrateLegacySettings({
    followedSbomComponentKeys: [' PURL:PKG:NPM/REACT@18.3.1 ', 7, null] as unknown as string[],
    disabledSbomComponentKeys: 'invalid' as unknown as string[],
    sbomFolders: [' reports ', '', null] as unknown as string[],
    settingsVersion: 2
  });

  assert.deepEqual(migrated.followedSbomComponentKeys, ['purl:pkg:npm/react@18.3.1']);
  assert.deepEqual(migrated.disabledSbomComponentKeys, []);
  assert.deepEqual(migrated.sbomFolders, ['reports']);
  assert.equal(migrated.settingsVersion, SETTINGS_VERSION);
});
