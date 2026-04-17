import { applyVulnCacheSchemaUpgrade, VULN_CACHE_DB_NAME, VULN_CACHE_DB_VERSION } from './VulnCacheSchema';

const getIndexedDbFactory = (): IDBFactory | null =>
  typeof indexedDB === 'undefined' ? null : indexedDB;

export const awaitRequest = <T>(request: IDBRequest<T>): Promise<T> =>
  new Promise<T>((resolve, reject) => {
    request.addEventListener('success', () => resolve(request.result));
    request.addEventListener('error', () => reject(request.error ?? new Error('IndexedDB request failed.')));
  });

export const awaitTransaction = (transaction: IDBTransaction): Promise<void> =>
  new Promise<void>((resolve, reject) => {
    transaction.addEventListener('complete', () => resolve());
    transaction.addEventListener('abort', () => reject(transaction.error ?? new Error('IndexedDB transaction aborted.')));
    transaction.addEventListener('error', () => reject(transaction.error ?? new Error('IndexedDB transaction failed.')));
  });

export class VulnCacheDb {
  private databasePromise: Promise<IDBDatabase> | null = null;

  public async close(): Promise<void> {
    if (!this.databasePromise) {
      return;
    }

    const database = await this.databasePromise;
    database.close();
    this.databasePromise = null;
  }

  public async open(): Promise<IDBDatabase> {
    if (!this.databasePromise) {
      this.databasePromise = this.openDatabase();
    }

    return this.databasePromise;
  }

  private async openDatabase(): Promise<IDBDatabase> {
    const indexedDbFactory = getIndexedDbFactory();
    if (!indexedDbFactory) {
      throw new Error('IndexedDB is not available in this runtime.');
    }

    const request = indexedDbFactory.open(VULN_CACHE_DB_NAME, VULN_CACHE_DB_VERSION);
    request.addEventListener('upgradeneeded', (event: IDBVersionChangeEvent) => {
      if (!request.result) {
        return;
      }

      applyVulnCacheSchemaUpgrade(request.result, event.oldVersion, event.newVersion);
    });

    return awaitRequest(request);
  }
}
