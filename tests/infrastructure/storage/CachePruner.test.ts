import assert from 'node:assert/strict';
import test from 'node:test';
import { CachePruner } from '../../../src/infrastructure/storage/CachePruner';

class FakeCacheRepository {
  public readonly callOrder: string[] = [];
  public readonly markSeenCalls: Array<{ purls: readonly string[]; seenAtMs: number }> = [];
  public activePurls: ReadonlySet<string> | null = null;
  public componentQueryExpiredCutoffMs: number | null = null;
  public expiredCutoffMs: number | null = null;
  public pruneBatchSize: number | null = null;

  public async markComponentQueriesSeen(purls: readonly string[], seenAtMs: number): Promise<void> {
    this.callOrder.push('markComponentQueriesSeen');
    this.markSeenCalls.push({ purls: [...purls], seenAtMs });
  }

  public async pruneOrphanedComponentQueries(activePurls: ReadonlySet<string>): Promise<number> {
    this.callOrder.push('pruneOrphanedComponentQueries');
    this.activePurls = activePurls;
    return 2;
  }

  public async pruneExpiredComponentQueries(cutoffMs: number): Promise<number> {
    this.callOrder.push('pruneExpiredComponentQueries');
    this.componentQueryExpiredCutoffMs = cutoffMs;
    return 5;
  }

  public async pruneExpired(cutoffMs: number, batchSize: number): Promise<number> {
    this.callOrder.push('pruneExpired');
    this.expiredCutoffMs = cutoffMs;
    this.pruneBatchSize = batchSize;
    return 3;
  }

  public async pruneToHardCap(hardCap: number, batchSize: number): Promise<number> {
    this.callOrder.push('pruneToHardCap');
    assert.equal(hardCap, 500);
    assert.equal(batchSize, 25);
    return 7;
  }
}

test('cache pruner enforces TTL and hard-cap policies deterministically', async () => {
  const repository = new FakeCacheRepository();
  const pruner = new CachePruner(repository as never, undefined, async () => [
    'pkg:npm/active@1.0.0',
    ' pkg:npm/active@1.0.0 ',
    '',
    'pkg:npm/other@2.0.0'
  ]);
  const now = Date.now();

  const result = await pruner.pruneNow({
    hardCap: 500,
    hydrateMaxItems: 200,
    hydratePageSize: 100,
    pruneBatchSize: 25,
    ttlMs: 60_000
  });

  assert.equal(result.componentQueryOrphanedCount, 2);
  assert.equal(result.componentQueryExpiredCount, 5);
  assert.equal(result.expiredCount, 3);
  assert.equal(result.overCapCount, 7);
  assert.deepEqual(repository.callOrder, [
    'markComponentQueriesSeen',
    'pruneOrphanedComponentQueries',
    'pruneExpiredComponentQueries',
    'pruneExpired',
    'pruneToHardCap'
  ]);
  assert.deepEqual(repository.markSeenCalls[0]?.purls, ['pkg:npm/active@1.0.0', 'pkg:npm/other@2.0.0']);
  assert.equal(repository.activePurls?.has('pkg:npm/active@1.0.0'), true);
  assert.equal(repository.activePurls?.has('pkg:npm/other@2.0.0'), true);
  assert.ok(repository.expiredCutoffMs !== null);
  assert.ok(repository.componentQueryExpiredCutoffMs !== null);
  assert.ok(Math.abs((repository.expiredCutoffMs ?? 0) - (now - 60_000)) < 5_000);
  assert.ok(Math.abs((repository.componentQueryExpiredCutoffMs ?? 0) - (now - 60_000)) < 5_000);
});
