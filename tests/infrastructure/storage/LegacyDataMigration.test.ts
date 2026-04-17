import assert from 'node:assert/strict';
import test from 'node:test';
import { LegacyDataMigration } from '../../../src/infrastructure/storage/LegacyDataMigration';
import type { FeedConfig } from '../../../src/application/services/types';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';

class FakeCacheRepository {
  public readonly imported: Array<{ lastSeenAt: string; sourceId: string; vulnerabilities: readonly Vulnerability[] }> = [];

  public async importLegacySnapshot(
    sourceId: string,
    vulnerabilities: readonly Vulnerability[],
    lastSeenAt: string
  ): Promise<void> {
    this.imported.push({ lastSeenAt, sourceId, vulnerabilities });
  }
}

class FakeSyncMetadataRepository {
  public readonly successes: Array<{ attemptedAt: string; sourceId: string; successfulAt: string }> = [];

  public async recordSuccess(sourceId: string, attemptedAt: string, successfulAt: string): Promise<void> {
    this.successes.push({ attemptedAt, sourceId, successfulAt });
  }
}

const feeds: FeedConfig[] = [
  { enabled: true, id: 'github-default', name: 'GitHub', type: 'github_advisory' },
  { enabled: true, id: 'nvd-default', name: 'NVD', type: 'nvd' }
];

const createVulnerability = (id: string, source: string): Vulnerability => ({
  affectedProducts: [],
  cvssScore: 7.5,
  id,
  publishedAt: '2026-01-01T00:00:00.000Z',
  references: [],
  severity: 'HIGH',
  source,
  summary: `${id} summary`,
  title: `${id} title`,
  updatedAt: '2026-01-01T00:00:00.000Z'
});

test('legacy migration moves persisted vulnerability arrays and cursors into the new storage layer', async () => {
  const cacheRepository = new FakeCacheRepository();
  const metadataRepository = new FakeSyncMetadataRepository();
  const migration = new LegacyDataMigration(cacheRepository as never, metadataRepository as never);

  const result = await migration.migrate({
    cache: [createVulnerability('GHSA-1', 'GitHub'), createVulnerability('CVE-1', 'NVD')],
    sourceSyncCursor: {
      GitHub: '2026-02-01T00:00:00.000Z',
      NVD: '2026-02-02T00:00:00.000Z'
    }
  }, feeds);

  assert.equal(result.migratedVulnerabilityCount, 2);
  assert.equal(result.migratedCursorCount, 2);
  assert.equal(result.removedLegacyFields, true);
  assert.deepEqual(cacheRepository.imported.map((entry) => entry.sourceId).sort(), ['github-default', 'nvd-default']);
  assert.deepEqual(metadataRepository.successes.map((entry) => entry.sourceId).sort(), ['github-default', 'nvd-default']);
});
