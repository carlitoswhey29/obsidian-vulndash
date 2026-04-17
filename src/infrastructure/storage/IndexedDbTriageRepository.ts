import type { TriageRecord } from '../../domain/triage/TriageRecord';
import { TriageRecord as TriageRecordEntity } from '../../domain/triage/TriageRecord';
import type { TriageRepository } from '../../domain/triage/TriageRepository';
import { awaitRequest, awaitTransaction, VulnCacheDb } from './VulnCacheDb';
import {
  createPersistedTriageRecord,
  type PersistedTriageRecord,
  VULN_CACHE_STORES
} from './VulnCacheSchema';

const toDomainRecord = (record: PersistedTriageRecord): TriageRecord =>
  TriageRecordEntity.create({
    correlationKey: record.correlationKey,
    source: record.source,
    state: record.state,
    updatedAt: record.updatedAt,
    vulnerabilityId: record.vulnerabilityId,
    ...(record.reason ? { reason: record.reason } : {}),
    ...(record.ticketRef ? { ticketRef: record.ticketRef } : {}),
    ...(record.updatedBy ? { updatedBy: record.updatedBy } : {})
  });

export class IndexedDbTriageRepository implements TriageRepository {
  public constructor(
    private readonly database: VulnCacheDb
  ) {}

  public async getByCorrelationKey(correlationKey: string): Promise<TriageRecord | null> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.triageRecords, 'readonly');
    const persistedRecord = await awaitRequest(
      transaction.objectStore(VULN_CACHE_STORES.triageRecords).get(correlationKey)
    );
    await awaitTransaction(transaction);

    return persistedRecord ? toDomainRecord(persistedRecord as PersistedTriageRecord) : null;
  }

  public async getByCorrelationKeys(correlationKeys: readonly string[]): Promise<ReadonlyMap<string, TriageRecord>> {
    if (correlationKeys.length === 0) {
      return new Map<string, TriageRecord>();
    }

    const uniqueKeys = Array.from(new Set(correlationKeys));
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.triageRecords, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.triageRecords);
    const requests = uniqueKeys.map((correlationKey) => ({
      correlationKey,
      request: store.get(correlationKey)
    }));
    const resolvedRecords = await Promise.all(requests.map(async ({ correlationKey, request }) => {
      const persistedRecord = await awaitRequest(request);
      return [correlationKey, persistedRecord as PersistedTriageRecord | undefined] as const;
    }));
    await awaitTransaction(transaction);

    const records = new Map<string, TriageRecord>();
    for (const [correlationKey, persistedRecord] of resolvedRecords) {
      if (!persistedRecord) {
        continue;
      }
      records.set(correlationKey, toDomainRecord(persistedRecord));
    }

    return records;
  }

  public async save(record: TriageRecord): Promise<TriageRecord> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.triageRecords, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.triageRecords);
    const existingRecord = await awaitRequest(store.get(record.correlationKey)) as PersistedTriageRecord | undefined;
    const nextPersistedRecord = createPersistedTriageRecord(record);

    if (existingRecord && existingRecord.updatedAtMs >= nextPersistedRecord.updatedAtMs) {
      await awaitTransaction(transaction);
      return toDomainRecord(existingRecord);
    }

    store.put(nextPersistedRecord);
    await awaitTransaction(transaction);
    return record;
  }
}
