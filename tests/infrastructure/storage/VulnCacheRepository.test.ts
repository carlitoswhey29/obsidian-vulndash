import assert from 'node:assert/strict';
import test from 'node:test';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { buildOsvVulnerabilityCacheKey } from '../../../src/infrastructure/clients/osv/OsvCacheKey';
import { VulnCacheRepository } from '../../../src/infrastructure/storage/VulnCacheRepository';
import type { PersistedComponentQueryRecord } from '../../../src/infrastructure/storage/VulnCacheSchema';
import { VULN_CACHE_STORES } from '../../../src/infrastructure/storage/VulnCacheSchema';

type RequestHandler<T> = () => T;

class MemoryRequest<T> {
  private readonly handlers = new Map<string, Array<() => void>>();
  public error: Error | null = null;
  public result: T;

  public constructor(handler: RequestHandler<T>) {
    this.result = handler();
    queueMicrotask(() => {
      for (const listener of this.handlers.get('success') ?? []) {
        listener();
      }
    });
  }

  public addEventListener(name: string, listener: () => void): void {
    const listeners = this.handlers.get(name) ?? [];
    listeners.push(listener);
    this.handlers.set(name, listeners);
  }
}

class MemoryObjectStore {
  private readonly records = new Map<string, Record<string, unknown>>();

  public constructor(private readonly keyPath: string) {}

  public get(key: string): MemoryRequest<Record<string, unknown> | undefined> {
    return new MemoryRequest(() => this.records.get(key));
  }

  public getAll(): MemoryRequest<Record<string, unknown>[]> {
    return new MemoryRequest(() => Array.from(this.records.entries())
      .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey))
      .map(([, value]) => value));
  }

  public put(value: Record<string, unknown>): MemoryRequest<Record<string, unknown>> {
    this.records.set(this.getKey(value), value);
    return new MemoryRequest(() => value);
  }

  public delete(key: string): MemoryRequest<undefined> {
    this.records.delete(key);
    return new MemoryRequest(() => undefined);
  }

  private getKey(value: Record<string, unknown>): string {
    const key = value[this.keyPath];
    if (typeof key !== 'string') {
      throw new Error(`Expected string key at ${this.keyPath}.`);
    }

    return key;
  }
}

class MemoryTransaction {
  private readonly handlers = new Map<string, Array<() => void>>();

  public constructor(private readonly stores: Map<string, MemoryObjectStore>) {}

  public addEventListener(name: string, listener: () => void): void {
    const listeners = this.handlers.get(name) ?? [];
    listeners.push(listener);
    this.handlers.set(name, listeners);

    if (name === 'complete') {
      queueMicrotask(() => listener());
    }
  }

  public objectStore(name: string): MemoryObjectStore {
    const store = this.stores.get(name);
    if (!store) {
      throw new Error(`Unknown object store: ${name}`);
    }

    return store;
  }

  public get error(): Error | null {
    return null;
  }
}

class MemoryDatabase {
  private readonly stores = new Map<string, MemoryObjectStore>();

  public addStore(name: string, keyPath: string): void {
    this.stores.set(name, new MemoryObjectStore(keyPath));
  }

  public transaction(storeNames: string | string[]): MemoryTransaction {
    const names = Array.isArray(storeNames) ? storeNames : [storeNames];
    return new MemoryTransaction(new Map(names.map((name) => {
      const store = this.stores.get(name);
      if (!store) {
        throw new Error(`Unknown object store: ${name}`);
      }

      return [name, store] as const;
    })));
  }
}

const createRepository = (): VulnCacheRepository => {
  const database = new MemoryDatabase();
  database.addStore(VULN_CACHE_STORES.componentQueries, 'purl');
  database.addStore(VULN_CACHE_STORES.vulnerabilities, 'cacheKey');
  return new VulnCacheRepository({
    open: async () => database as unknown as IDBDatabase
  } as never);
};

const createComponentQueryRecord = (
  purl: string,
  overrides: Partial<PersistedComponentQueryRecord> = {}
): PersistedComponentQueryRecord => ({
  purl,
  source: 'osv',
  lastQueriedAtMs: 1_710_000_000_000,
  lastSeenInWorkspaceAtMs: 1_710_000_100_000,
  resultState: 'hit',
  vulnerabilityCacheKeys: [buildOsvVulnerabilityCacheKey('OSV-2026-1')],
  ...overrides
});

const createVulnerability = (id: string): Vulnerability => ({
  affectedProducts: [],
  cvssScore: 8.1,
  id,
  publishedAt: '2026-01-01T00:00:00.000Z',
  references: [`https://example.com/${id}`],
  severity: 'HIGH',
  source: 'OSV',
  summary: `${id} summary`,
  title: `${id} title`,
  updatedAt: '2026-01-02T00:00:00.000Z'
});

test('component query records round-trip by PURL', async () => {
  const repository = createRepository();
  const record = createComponentQueryRecord('pkg:npm/example@1.0.0');

  await repository.saveComponentQueries([record]);
  const loaded = await repository.loadComponentQueries([record.purl, 'pkg:npm/missing@1.0.0']);

  assert.equal(loaded.size, 1);
  assert.deepEqual(loaded.get(record.purl), record);
  assert.equal(loaded.has('pkg:npm/missing@1.0.0'), false);
});

test('markComponentQueriesSeen updates only requested PURLs', async () => {
  const repository = createRepository();
  const first = createComponentQueryRecord('pkg:npm/first@1.0.0', {
    lastSeenInWorkspaceAtMs: 100
  });
  const second = createComponentQueryRecord('pkg:npm/second@1.0.0', {
    lastSeenInWorkspaceAtMs: 200
  });

  await repository.saveComponentQueries([first, second]);
  await repository.markComponentQueriesSeen([first.purl], 500);
  const loaded = await repository.loadComponentQueries([first.purl, second.purl]);

  assert.equal(loaded.get(first.purl)?.lastSeenInWorkspaceAtMs, 500);
  assert.equal(loaded.get(second.purl)?.lastSeenInWorkspaceAtMs, 200);
});

test('pruneOrphanedComponentQueries removes only inactive PURLs', async () => {
  const repository = createRepository();
  const activeOne = createComponentQueryRecord('pkg:npm/active-one@1.0.0');
  const activeTwo = createComponentQueryRecord('pkg:npm/active-two@1.0.0');
  const orphaned = createComponentQueryRecord('pkg:npm/orphaned@1.0.0');

  await repository.saveComponentQueries([activeOne, activeTwo, orphaned]);
  const deleted = await repository.pruneOrphanedComponentQueries(new Set([activeOne.purl, activeTwo.purl]));
  const loaded = await repository.loadComponentQueries([activeOne.purl, activeTwo.purl, orphaned.purl]);

  assert.equal(deleted, 1);
  assert.equal(loaded.has(activeOne.purl), true);
  assert.equal(loaded.has(activeTwo.purl), true);
  assert.equal(loaded.has(orphaned.purl), false);
});

test('pruneExpiredComponentQueries removes only stale records', async () => {
  const repository = createRepository();
  const stale = createComponentQueryRecord('pkg:npm/stale@1.0.0', {
    lastQueriedAtMs: 99
  });
  const boundary = createComponentQueryRecord('pkg:npm/boundary@1.0.0', {
    lastQueriedAtMs: 100
  });
  const fresh = createComponentQueryRecord('pkg:npm/fresh@1.0.0', {
    lastQueriedAtMs: 101
  });

  await repository.saveComponentQueries([stale, boundary, fresh]);
  const deleted = await repository.pruneExpiredComponentQueries(100);
  const loaded = await repository.loadComponentQueries([stale.purl, boundary.purl, fresh.purl]);

  assert.equal(deleted, 1);
  assert.equal(loaded.has(stale.purl), false);
  assert.equal(loaded.has(boundary.purl), true);
  assert.equal(loaded.has(fresh.purl), true);
});

test('loadVulnerabilitiesByCacheKeys rehydrates persisted vulnerabilities by composite cache key', async () => {
  const repository = createRepository();
  const first = createVulnerability('OSV-2026-1');
  const second = createVulnerability('OSV-2026-2');

  await repository.importLegacySnapshot('osv', [first, second], '2026-04-22T00:00:00.000Z');
  const loaded = await repository.loadVulnerabilitiesByCacheKeys([
    buildOsvVulnerabilityCacheKey(second.id),
    buildOsvVulnerabilityCacheKey('OSV-2026-missing'),
    buildOsvVulnerabilityCacheKey(first.id)
  ]);

  assert.deepEqual(loaded.map((vulnerability) => vulnerability.id), [second.id, first.id]);
});
