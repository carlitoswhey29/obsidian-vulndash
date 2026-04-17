import { buildVulnerabilityCacheKey } from '../../application/pipeline/PipelineTypes';
import type { PipelineSnapshot } from '../../application/pipeline/PipelineTypes';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { awaitTransaction, VulnCacheDb } from './VulnCacheDb';
import {
  comparePersistedRecordsForHardCap,
  createPersistedVulnerabilityRecord,
  type PersistedVulnerabilityRecord,
  VULN_CACHE_INDEXES,
  VULN_CACHE_STORES
} from './VulnCacheSchema';

export class VulnCacheRepository {
  public constructor(private readonly database: VulnCacheDb) {}

  public async count(): Promise<number> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const count = await this.awaitRequest(transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).count());
    await awaitTransaction(transaction);
    return count;
  }

  public async loadLatest(limit: number, pageSize: number): Promise<Vulnerability[]> {
    if (limit <= 0) {
      return [];
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const index = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).index(VULN_CACHE_INDEXES.byRetentionRank);
    const records = await this.collectCursorValues(index.openCursor(null, 'prev'), limit, pageSize);
    await awaitTransaction(transaction);
    return records.map((record) => record.vulnerability);
  }

  public async loadSourceSnapshot(sourceId: string): Promise<PipelineSnapshot> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const index = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).index(VULN_CACHE_INDEXES.bySourceId);
    const records = await this.collectCursorValues(index.openCursor(IDBKeyRange.only(sourceId)), Number.POSITIVE_INFINITY, 250);
    await awaitTransaction(transaction);

    const cacheByKey = new Map<string, Vulnerability>();
    const originByKey = new Map<string, string>();
    for (const record of records) {
      const runtimeCacheKey = buildVulnerabilityCacheKey(record.vulnerability);
      cacheByKey.set(runtimeCacheKey, record.vulnerability);
      originByKey.set(runtimeCacheKey, sourceId);
    }

    return {
      cacheByKey,
      originByKey
    };
  }

  public async pruneExpired(cutoffMs: number, batchSize: number): Promise<number> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.byLastSeenAt);
    let deleted = 0;

    await this.iterateCursor(index.openCursor(IDBKeyRange.upperBound(cutoffMs)), async (cursor) => {
      store.delete(cursor.primaryKey);
      deleted += 1;
      return deleted % Math.max(batchSize, 1) === 0;
    });

    await awaitTransaction(transaction);
    return deleted;
  }

  public async pruneToHardCap(hardCap: number, batchSize: number): Promise<number> {
    const count = await this.count();
    if (count <= hardCap) {
      return 0;
    }

    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.byRetentionRank);
    let seen = 0;
    let deleted = 0;

    await this.iterateCursor(index.openCursor(null, 'prev'), async (cursor) => {
      seen += 1;
      if (seen <= hardCap) {
        return seen % Math.max(batchSize, 1) === 0;
      }

      store.delete(cursor.primaryKey);
      deleted += 1;
      return deleted % Math.max(batchSize, 1) === 0;
    });

    await awaitTransaction(transaction);
    return deleted;
  }

  public async replaceSourceSnapshot(
    sourceId: string,
    vulnerabilities: readonly Vulnerability[],
    syncedAt: string
  ): Promise<void> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const index = store.index(VULN_CACHE_INDEXES.bySourceId);
    const existingRecords = await this.collectCursorValues(index.openCursor(IDBKeyRange.only(sourceId)), Number.POSITIVE_INFINITY, 250);
    const existingKeys = new Set(existingRecords.map((record) => record.cacheKey));
    const retainedKeys = new Set<string>();
    const createdAtMs = Date.now();

    for (const vulnerability of vulnerabilities) {
      const record = createPersistedVulnerabilityRecord(sourceId, vulnerability, syncedAt, createdAtMs);
      retainedKeys.add(record.cacheKey);
      store.put(record);
    }

    for (const key of existingKeys) {
      if (!retainedKeys.has(key)) {
        store.delete(key);
      }
    }

    await awaitTransaction(transaction);
  }

  public async importLegacySnapshot(
    sourceId: string,
    vulnerabilities: readonly Vulnerability[],
    lastSeenAt: string
  ): Promise<void> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readwrite');
    const store = transaction.objectStore(VULN_CACHE_STORES.vulnerabilities);
    const createdAtMs = Date.now();

    for (const vulnerability of vulnerabilities) {
      store.put(createPersistedVulnerabilityRecord(sourceId, vulnerability, lastSeenAt, createdAtMs));
    }

    await awaitTransaction(transaction);
  }

  public async listPersistedRecords(): Promise<PersistedVulnerabilityRecord[]> {
    const db = await this.database.open();
    const transaction = db.transaction(VULN_CACHE_STORES.vulnerabilities, 'readonly');
    const records = await this.collectCursorValues(
      transaction.objectStore(VULN_CACHE_STORES.vulnerabilities).openCursor(),
      Number.POSITIVE_INFINITY,
      250
    );
    await awaitTransaction(transaction);
    return records.sort(comparePersistedRecordsForHardCap);
  }

  private async awaitRequest<T>(request: IDBRequest<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      request.addEventListener('success', () => resolve(request.result));
      request.addEventListener('error', () => reject(request.error ?? new Error('IndexedDB request failed.')));
    });
  }

  private async collectCursorValues(
    request: IDBRequest<IDBCursorWithValue | null>,
    limit: number,
    pageSize: number
  ): Promise<PersistedVulnerabilityRecord[]> {
    const values: PersistedVulnerabilityRecord[] = [];
    await this.iterateCursor(request, async (cursor) => {
      values.push(cursor.value as PersistedVulnerabilityRecord);
      return values.length % Math.max(pageSize, 1) === 0;
    }, limit);
    return values;
  }

  private async iterateCursor(
    request: IDBRequest<IDBCursorWithValue | null>,
    onCursor: (cursor: IDBCursorWithValue) => Promise<boolean> | boolean,
    limit = Number.POSITIVE_INFINITY
  ): Promise<void> {
    let seen = 0;

    await new Promise<void>((resolve, reject) => {
      request.addEventListener('error', () => reject(request.error ?? new Error('IndexedDB cursor failed.')));
      request.addEventListener('success', () => {
        const cursor = request.result;
        if (!cursor || seen >= limit) {
          resolve();
          return;
        }

        void (async () => {
          try {
            seen += 1;
            const shouldYield = await onCursor(cursor);
            if (seen >= limit) {
              resolve();
              return;
            }

            if (shouldYield) {
              setTimeout(() => cursor.continue(), 0);
              return;
            }

            cursor.continue();
          } catch (error) {
            reject(error);
          }
        })();
      });
    });
  }
}
