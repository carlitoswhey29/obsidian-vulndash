import { CooperativeScheduler } from '../async/CooperativeScheduler';
import { VulnCacheRepository } from './VulnCacheRepository';
import type { CacheRetentionSettings } from './VulnCacheSchema';

export interface CachePruneResult {
  readonly componentQueryExpiredCount: number;
  readonly componentQueryOrphanedCount: number;
  readonly expiredCount: number;
  readonly overCapCount: number;
}

export class CachePruner {
  private scheduled = false;

  public constructor(
    private readonly repository: VulnCacheRepository,
    private readonly scheduler = new CooperativeScheduler(),
    private readonly getActivePurls?: () => Promise<readonly string[]>
  ) {}

  public schedule(policy: CacheRetentionSettings): void {
    if (this.scheduled) {
      return;
    }

    this.scheduled = true;
    const run = async (): Promise<void> => {
      try {
        await this.scheduler.yieldToHost({ timeoutMs: 50 });
        const result = await this.pruneNow(policy);
        console.info('[vulndash.cache.prune.complete]', result);
      } catch (error) {
        console.warn('[vulndash.cache.prune_failed]', error);
      } finally {
        this.scheduled = false;
      }
    };

    void run();
  }

  public async pruneNow(policy: CacheRetentionSettings): Promise<CachePruneResult> {
    const nowMs = Date.now();
    const activePurls = this.toOrderedUniqueStrings(await this.getActivePurls?.() ?? []);
    const activePurlSet = new Set(activePurls);

    if (activePurls.length > 0) {
      await this.repository.markComponentQueriesSeen(activePurls, nowMs);
    }

    const componentQueryOrphanedCount = activePurls.length > 0
      ? await this.repository.pruneOrphanedComponentQueries(activePurlSet)
      : 0;
    const componentQueryExpiredCount = await this.repository.pruneExpiredComponentQueries(nowMs - policy.ttlMs);
    const expiredCount = await this.repository.pruneExpired(nowMs - policy.ttlMs, policy.pruneBatchSize);
    const overCapCount = await this.repository.pruneToHardCap(policy.hardCap, policy.pruneBatchSize);

    return {
      componentQueryExpiredCount,
      componentQueryOrphanedCount,
      expiredCount,
      overCapCount
    };
  }

  private toOrderedUniqueStrings(values: readonly string[]): string[] {
    const normalizedValues: string[] = [];
    const seen = new Set<string>();

    for (const value of values) {
      const normalized = value.trim();
      if (!normalized || seen.has(normalized)) {
        continue;
      }

      seen.add(normalized);
      normalizedValues.push(normalized);
    }

    return normalizedValues;
  }
}
