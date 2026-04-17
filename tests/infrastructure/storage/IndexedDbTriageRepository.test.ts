import assert from 'node:assert/strict';
import test from 'node:test';
import { IndexedDbTriageRepository } from '../../../src/infrastructure/storage/IndexedDbTriageRepository';
import { TriageRecord } from '../../../src/domain/triage/TriageRecord';

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

class MemoryTransaction {
  private readonly handlers = new Map<string, Array<() => void>>();
  private readonly store: MemoryObjectStore;

  public constructor(store: MemoryObjectStore) {
    this.store = store;
  }

  public addEventListener(name: string, listener: () => void): void {
    const listeners = this.handlers.get(name) ?? [];
    listeners.push(listener);
    this.handlers.set(name, listeners);
    if (name === 'complete') {
      queueMicrotask(() => listener());
    }
  }

  public objectStore(): MemoryObjectStore {
    return this.store;
  }

  public get error(): Error | null {
    return null;
  }
}

class MemoryObjectStore {
  private readonly records = new Map<string, Record<string, unknown>>();

  public get(key: string): MemoryRequest<Record<string, unknown> | undefined> {
    return new MemoryRequest(() => this.records.get(key));
  }

  public put(value: Record<string, unknown>): MemoryRequest<Record<string, unknown>> {
    this.records.set(String(value.correlationKey), value);
    return new MemoryRequest(() => value);
  }
}

class MemoryDatabase {
  private readonly store = new MemoryObjectStore();

  public transaction(): MemoryTransaction {
    return new MemoryTransaction(this.store);
  }
}

test('indexeddb triage repository round-trips records and keeps the newest update', async () => {
  const memoryDatabase = new MemoryDatabase();
  const database = {
    open: async () => memoryDatabase as unknown as IDBDatabase
  };
  const repository = new IndexedDbTriageRepository(database as never);
  const first = TriageRecord.create({
    correlationKey: 'nvd::cve-2026-0001',
    source: 'NVD',
    state: 'investigating',
    updatedAt: '2026-04-17T14:30:00.000Z',
    vulnerabilityId: 'CVE-2026-0001'
  });
  const second = TriageRecord.create({
    correlationKey: 'nvd::cve-2026-0001',
    source: 'NVD',
    state: 'mitigated',
    updatedAt: '2026-04-17T14:31:00.000Z',
    vulnerabilityId: 'CVE-2026-0001'
  });

  await repository.save(first);
  await repository.save(second);
  const loaded = await repository.getByCorrelationKey('nvd::cve-2026-0001');
  const loadedMany = await repository.getByCorrelationKeys(['nvd::cve-2026-0001', 'nvd::missing']);

  assert.equal(loaded?.state, 'mitigated');
  assert.equal(loadedMany.get('nvd::cve-2026-0001')?.state, 'mitigated');
  assert.equal(loadedMany.has('nvd::missing'), false);
});

