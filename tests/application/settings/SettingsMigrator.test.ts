import assert from 'node:assert/strict';
import test from 'node:test';
import { BUILT_IN_FEEDS, FEED_TYPES } from '../../../src/domain/feeds/FeedTypes';
import {
  SettingsMigrator,
  migrateLegacySettings
} from '../../../src/application/settings/SettingsMigrator';
import {
  DEFAULT_SETTINGS,
  SETTINGS_VERSION
} from '../../../src/application/use-cases/DefaultSettings';

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

test('migrateLegacySettings maps legacy auto-note settings into the daily rollup configuration', () => {
  const migrated = migrateLegacySettings({
    autoHighNoteCreationEnabled: true,
    autoNoteCreationEnabled: true,
    autoNoteFolder: 'Ops Briefings',
    settingsVersion: 7
  });

  assert.equal(migrated.dailyRollup.folderPath, 'Ops Briefings');
  assert.equal(migrated.dailyRollup.autoGenerateOnFirstSyncOfDay, true);
  assert.equal(migrated.dailyRollup.severityThreshold, 'HIGH');
});

test('migrateLegacySettings preserves legacy SBOM data and rekeys feed cursors without losing overrides', () => {
  const migrated = migrateLegacySettings({
    productFilters: ['Portal Web'],
    sbomPath: 'reports/legacy.json',
    sboms: [
      {
        contentHash: '',
        components: [
          {
            excluded: true,
            name: 'Portal Web',
            normalizedName: 'Portal Control Plane'
          }
        ],
        enabled: true,
        id: 'legacy-sbom',
        label: 'Legacy SBOM',
        lastImportedAt: 0,
        path: 'reports/legacy.json'
      }
    ],
    settingsVersion: 4,
    sourceSyncCursor: {
      GitHub: 'github-cursor',
      NVD: 'nvd-cursor'
    }
  });

  assert.deepEqual(migrated.manualProductFilters, ['Portal Web']);
  assert.deepEqual(migrated.productFilters, ['Portal Web']);
  assert.deepEqual(migrated.sboms, [{
    contentHash: '',
    enabled: true,
    id: 'legacy-sbom',
    label: 'Legacy SBOM',
    lastImportedAt: 0,
    path: 'reports/legacy.json'
  }]);
  assert.deepEqual(migrated.sbomOverrides, {
    'legacy-sbom::Portal Web': {
      editedName: 'Portal Control Plane',
      excluded: true
    }
  });
  assert.equal(migrated.sourceSyncCursor[BUILT_IN_FEEDS.NVD.id], 'nvd-cursor');
  assert.equal(migrated.sourceSyncCursor[BUILT_IN_FEEDS.GITHUB_ADVISORY.id], 'github-cursor');
  assert.equal(migrated.sourceSyncCursor.NVD, undefined);
  assert.equal(migrated.sourceSyncCursor.GitHub, undefined);
  assert.equal(migrated.settingsVersion, SETTINGS_VERSION);
});

test('migrateLegacySettings normalizes invalid OSV feed values predictably', () => {
  const migrated = migrateLegacySettings({
    feeds: [
      {
        id: BUILT_IN_FEEDS.OSV.id,
        name: BUILT_IN_FEEDS.OSV.name,
        type: FEED_TYPES.OSV,
        enabled: true,
        cacheTtlMs: 0,
        negativeCacheTtlMs: -1,
        requestTimeoutMs: Number.NaN,
        maxConcurrentBatches: 99
      }
    ]
  });

  const osvFeed = migrated.feeds.find((feed) => feed.type === FEED_TYPES.OSV);

  assert.ok(osvFeed);
  assert.equal(osvFeed?.enabled, true);
  assert.equal(osvFeed?.cacheTtlMs, 21_600_000);
  assert.equal(osvFeed?.negativeCacheTtlMs, 3_600_000);
  assert.equal(osvFeed?.requestTimeoutMs, 15_000);
  assert.equal(osvFeed?.maxConcurrentBatches, 8);
});

test('SettingsMigrator is idempotent for current settings', () => {
  const migrator = new SettingsMigrator();
  const result = migrator.migrate(DEFAULT_SETTINGS);

  assert.equal(result.didMigrate, false);
  assert.equal(result.fromVersion, SETTINGS_VERSION);
  assert.equal(result.toVersion, SETTINGS_VERSION);
  assert.deepEqual(result.appliedSteps, []);
  assert.deepEqual(result.settings, DEFAULT_SETTINGS);
});
