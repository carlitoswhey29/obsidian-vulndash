import assert from 'node:assert/strict';
import test from 'node:test';
import { buildPersistedSettingsSnapshot, DEFAULT_SETTINGS, SETTINGS_VERSION } from '../src/plugin';

test('buildPersistedSettingsSnapshot keeps persisted SBOM settings lean and normalized', () => {
  const snapshot = buildPersistedSettingsSnapshot({
    ...DEFAULT_SETTINGS,
    manualProductFilters: ['Portal Web'],
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
  assert.deepEqual(snapshot.sbomOverrides, {
    'sbom-1::portal-web': { editedName: 'Portal Web' }
  });
  assert.deepEqual(snapshot.manualProductFilters, ['Portal Web']);
  assert.deepEqual(snapshot.productFilters, ['Portal Web', 'Gateway Service']);
});
