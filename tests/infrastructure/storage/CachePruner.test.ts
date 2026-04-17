import assert from 'node:assert/strict';
import test from 'node:test';
import { CachePruner } from '../../../src/infrastructure/storage/CachePruner';

class FakeCacheRepository {
  public expiredCutoffMs: number | null = null;
  public pruneBatchSize: number | null = null;

  public async pruneExpired(cutoffMs: number, batchSize: number): Promise<number> {
    this.expiredCutoffMs = cutoffMs;
    this.pruneBatchSize = batchSize;
    return 3;
  }

  public async pruneToHardCap(hardCap: number, batchSize: number): Promise<number> {
    assert.equal(hardCap, 500);
    assert.equal(batchSize, 25);
    return 7;
  }
}

test('cache pruner enforces TTL and hard-cap policies deterministically', async () => {
  const repository = new FakeCacheRepository();
  const pruner = new CachePruner(repository as never);
  const now = Date.now();

  const result = await pruner.pruneNow({
    hardCap: 500,
    hydrateMaxItems: 200,
    hydratePageSize: 100,
    pruneBatchSize: 25,
    ttlMs: 60_000
  });

  assert.equal(result.expiredCount, 3);
  assert.equal(result.overCapCount, 7);
  assert.ok(repository.expiredCutoffMs !== null);
  assert.ok(Math.abs((repository.expiredCutoffMs ?? 0) - (now - 60_000)) < 5_000);
});
