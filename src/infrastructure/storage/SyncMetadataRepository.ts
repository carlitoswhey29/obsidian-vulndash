import { awaitRequest, awaitTransaction, VulnCacheDb } from './VulnCacheDb';
import { type PersistedSyncMetadataRecord, VULN_CACHE_DB_VERSION, VULN_CACHE_STORES } from './VulnCacheSchema';

export class SyncMetadataRepository {
  public constructor(private readonly database: VulnCacheDb) {}

  public async getAllLastSuccessfulSyncAt(): Promise<Record<string, string>> {
    const records = await this.listRecords();
    return Object.fromEntries(records.flatMap((record) => (
      record.lastSuccessfulSyncAt ? [[record.sourceId, record.lastSuccessfulSyncAt] as const] : []
    )));
  }

  public async getRecord(sourceId: string): Promise<PersistedSyncMetadataRecord | null> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.syncMetadata, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.syncMetadata);
    const record = await awaitRequest(store.get(sourceId)) as PersistedSyncMetadataRecord | undefined;
    await awaitTransaction(transaction);
    return record ?? null;
  }

  public async getLastSuccessfulSyncAt(sourceId: string): Promise<string | null> {
    return (await this.getRecord(sourceId))?.lastSuccessfulSyncAt ?? null;
  }

  public async listRecords(): Promise<PersistedSyncMetadataRecord[]> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.syncMetadata, 'readonly');
    const store = transaction.objectStore(VULN_CACHE_STORES.syncMetadata);
    const records = await awaitRequest(store.getAll()) as PersistedSyncMetadataRecord[];
    await awaitTransaction(transaction);
    return records.sort((left, right) => left.sourceId.localeCompare(right.sourceId));
  }

  public async recordAttempt(sourceId: string, attemptedAt: string): Promise<void> {
    const existing = await this.getRecord(sourceId);
    await this.putRecord({
      cacheSchemaVersion: VULN_CACHE_DB_VERSION,
      lastAttemptedSyncAt: attemptedAt,
      ...(existing?.lastSuccessfulSyncAt ? { lastSuccessfulSyncAt: existing.lastSuccessfulSyncAt } : {}),
      sourceId,
      updatedAtMs: Date.now()
    });
  }

  public async recordSuccess(sourceId: string, attemptedAt: string, successfulAt: string): Promise<void> {
    await this.putRecord({
      cacheSchemaVersion: VULN_CACHE_DB_VERSION,
      lastAttemptedSyncAt: attemptedAt,
      lastSuccessfulSyncAt: successfulAt,
      sourceId,
      updatedAtMs: Date.now()
    });
  }

  private async putRecord(record: PersistedSyncMetadataRecord): Promise<void> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.syncMetadata, 'readwrite');
    transaction.objectStore(VULN_CACHE_STORES.syncMetadata).put(record);
    await awaitTransaction(transaction);
  }
}
