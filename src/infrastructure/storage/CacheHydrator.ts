import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { CooperativeScheduler } from '../async/CooperativeScheduler';
import { VulnCacheRepository } from './VulnCacheRepository';

export interface CacheHydrationOptions {
  readonly limit: number;
  readonly pageSize: number;
}

export class CacheHydrator {
  public constructor(
    private readonly repository: VulnCacheRepository,
    private readonly scheduler = new CooperativeScheduler()
  ) {}

  public async hydrateLatest(options: CacheHydrationOptions): Promise<Vulnerability[]> {
    const hydrated = await this.repository.loadLatest(options.limit, options.pageSize);
    if (hydrated.length > options.pageSize) {
      await this.scheduler.yieldToHost({ timeoutMs: 16 });
    }
    return hydrated;
  }
}
