import assert from 'node:assert/strict';
import test from 'node:test';
import { applyVulnCacheSchemaUpgrade, VULN_CACHE_INDEXES, VULN_CACHE_STORES } from '../../../src/infrastructure/storage/VulnCacheSchema';

class FakeDomStringList {
  private readonly values = new Set<string>();

  public contains(name: string): boolean {
    return this.values.has(name);
  }

  public add(name: string): void {
    this.values.add(name);
  }
}

class FakeStore {
  public readonly indexNames = new FakeDomStringList();
  public readonly keyPath: string | string[] | null;

  public constructor(keyPath: string | string[] | null) {
    this.keyPath = keyPath;
  }

  public createIndex(name: string): void {
    this.indexNames.add(name);
  }
}

class FakeDatabase {
  public readonly objectStoreNames = new FakeDomStringList();
  private readonly stores = new Map<string, FakeStore>();

  public createObjectStore(name: string, options?: IDBObjectStoreParameters): FakeStore {
    this.objectStoreNames.add(name);
    const store = new FakeStore(options?.keyPath ?? null);
    this.stores.set(name, store);
    return store;
  }

  public transaction(storeNames: string | string[]) {
    const firstStore = Array.isArray(storeNames) ? storeNames[0] : storeNames;
    return {
      objectStore: (name: string): FakeStore => this.stores.get(name) ?? this.stores.get(firstStore ?? '') ?? new FakeStore(null)
    };
  }

  public getStore(name: string): FakeStore | undefined {
    return this.stores.get(name);
  }
}

test('schema upgrade creates vulnerability, triage, and sync metadata stores with required indexes', () => {
  const database = new FakeDatabase();

  applyVulnCacheSchemaUpgrade(database as unknown as IDBDatabase, 0, 3);

  const vulnerabilities = database.getStore(VULN_CACHE_STORES.vulnerabilities);
  assert.ok(vulnerabilities);
  assert.equal(vulnerabilities?.keyPath, 'cacheKey');
  assert.equal(vulnerabilities?.indexNames.contains(VULN_CACHE_INDEXES.bySourceId), true);
  assert.equal(vulnerabilities?.indexNames.contains(VULN_CACHE_INDEXES.byLastSeenAt), true);
  assert.equal(vulnerabilities?.indexNames.contains(VULN_CACHE_INDEXES.byRetentionRank), true);
  const triageRecords = database.getStore(VULN_CACHE_STORES.triageRecords);
  assert.ok(triageRecords);
  assert.equal(triageRecords?.keyPath, 'correlationKey');
  assert.equal(triageRecords?.indexNames.contains(VULN_CACHE_INDEXES.triageByState), true);
  assert.equal(triageRecords?.indexNames.contains(VULN_CACHE_INDEXES.triageByUpdatedAt), true);
  assert.ok(database.getStore(VULN_CACHE_STORES.syncMetadata));
  assert.ok(database.getStore(VULN_CACHE_STORES.databaseMetadata));
  const componentQueries = database.getStore(VULN_CACHE_STORES.componentQueries);
  assert.ok(componentQueries);
  assert.equal(componentQueries?.keyPath, 'purl');
});

test('schema upgrade from version 2 adds the componentQueries store', () => {
  const database = new FakeDatabase();
  database.createObjectStore(VULN_CACHE_STORES.vulnerabilities, { keyPath: 'cacheKey' });
  database.createObjectStore(VULN_CACHE_STORES.syncMetadata, { keyPath: 'sourceId' });
  database.createObjectStore(VULN_CACHE_STORES.databaseMetadata, { keyPath: 'key' });
  database.createObjectStore(VULN_CACHE_STORES.triageRecords, { keyPath: 'correlationKey' });

  applyVulnCacheSchemaUpgrade(database as unknown as IDBDatabase, 2, 3);

  const componentQueries = database.getStore(VULN_CACHE_STORES.componentQueries);
  assert.ok(componentQueries);
  assert.equal(componentQueries?.keyPath, 'purl');
});
