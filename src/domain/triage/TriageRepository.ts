import type { TriageRecord } from './TriageRecord';

export interface TriageRepository {
  getByCorrelationKey(correlationKey: string): Promise<TriageRecord | null>;
  getByCorrelationKeys(correlationKeys: readonly string[]): Promise<ReadonlyMap<string, TriageRecord>>;
  save(record: TriageRecord): Promise<TriageRecord>;
}
