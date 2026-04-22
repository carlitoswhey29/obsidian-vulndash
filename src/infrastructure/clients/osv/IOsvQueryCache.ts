import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import type { PersistedComponentQueryRecord } from '../../storage/VulnCacheSchema';

export interface IOsvQueryCache {
  loadComponentQueries(purls: readonly string[]): Promise<Map<string, PersistedComponentQueryRecord>>;
  saveComponentQueries(records: readonly PersistedComponentQueryRecord[]): Promise<void>;
  markComponentQueriesSeen(purls: readonly string[], seenAtMs: number): Promise<void>;
  pruneOrphanedComponentQueries(activePurls: ReadonlySet<string>): Promise<number>;
  pruneExpiredComponentQueries(cutoffMs: number): Promise<number>;
  loadVulnerabilitiesByCacheKeys(keys: readonly string[]): Promise<readonly Vulnerability[]>;
}
