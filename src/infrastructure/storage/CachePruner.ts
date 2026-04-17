import { CooperativeScheduler } from '../async/CooperativeScheduler';
import { VulnCacheRepository } from './VulnCacheRepository';
import type { CacheRetentionSettings } from './VulnCacheSchema';

export interface CachePruneResult {
  readonly expiredCount: number;
  readonly overCapCount: number;
}

export class CachePruner {
  private scheduled = false;

  public constructor(
    private readonly repository: VulnCacheRepository,
    private readonly scheduler = new CooperativeScheduler()
  ) {}

  public schedule(policy: CacheRetentionSettings): void {
    if (this.scheduled) {
      return;
    }

    this.scheduled = true;
    const run = async (): Promise<void> => {
      try {
        await this.scheduler.yieldToHost({ timeoutMs: 50 });
        await this.pruneNow(policy);
      } catch (error) {
        console.warn('[vulndash.cache.prune_failed]', error);
      } finally {
        this.scheduled = false;
      }
    };

    void run();
  }

  public async pruneNow(policy: CacheRetentionSettings): Promise<CachePruneResult> {
    const expiredCount = await this.repository.pruneExpired(Date.now() - policy.ttlMs, policy.pruneBatchSize);
    const overCapCount = await this.repository.pruneToHardCap(policy.hardCap, policy.pruneBatchSize);

    return {
      expiredCount,
      overCapCount
    };
  }
}
