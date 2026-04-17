import assert from 'node:assert/strict';
import test from 'node:test';
import { FilterByTriageState } from '../../../src/application/triage/FilterByTriageState';
import { JoinTriageState } from '../../../src/application/triage/JoinTriageState';
import { SetTriageState } from '../../../src/application/triage/SetTriageState';
import type { Vulnerability } from '../../../src/domain/entities/Vulnerability';
import { TriageRecord } from '../../../src/domain/triage/TriageRecord';
import type { TriageRepository } from '../../../src/domain/triage/TriageRepository';

class MemoryTriageRepository implements TriageRepository {
  private readonly records = new Map<string, TriageRecord>();

  public async getByCorrelationKey(correlationKey: string): Promise<TriageRecord | null> {
    return this.records.get(correlationKey) ?? null;
  }

  public async getByCorrelationKeys(correlationKeys: readonly string[]): Promise<ReadonlyMap<string, TriageRecord>> {
    const records = new Map<string, TriageRecord>();
    for (const key of correlationKeys) {
      const record = this.records.get(key);
      if (record) {
        records.set(key, record);
      }
    }
    return records;
  }

  public async save(record: TriageRecord): Promise<TriageRecord> {
    const existing = this.records.get(record.correlationKey);
    if (existing && Date.parse(existing.updatedAt) >= Date.parse(record.updatedAt)) {
      return existing;
    }

    this.records.set(record.correlationKey, record);
    return record;
  }
}

const createVulnerability = (overrides: Partial<Vulnerability> = {}): Vulnerability => ({
  affectedProducts: ['demo-app'],
  cvssScore: 8.1,
  id: 'CVE-2026-0001',
  publishedAt: '2026-04-01T12:00:00.000Z',
  references: ['https://example.com/CVE-2026-0001'],
  severity: 'HIGH',
  source: 'NVD',
  summary: 'Demo summary',
  title: 'Demo vulnerability',
  updatedAt: '2026-04-02T12:00:00.000Z',
  ...overrides
});

test('set triage state issues monotonic updates and join triage preserves input ordering', async () => {
  const repository = new MemoryTriageRepository();
  const setTriageState = new SetTriageState(repository);
  const joinTriageState = new JoinTriageState(repository);
  const first = createVulnerability();
  const second = createVulnerability({ id: 'CVE-2026-0002' });

  const saved = await setTriageState.execute({
    state: 'investigating',
    vulnerability: first
  });
  const newer = await setTriageState.execute({
    state: 'mitigated',
    vulnerability: first
  });
  const joined = await joinTriageState.execute([second, first]);

  assert.ok(Date.parse(newer.updatedAt) > Date.parse(saved.updatedAt));
  assert.equal(joined[0]?.vulnerability.id, 'CVE-2026-0002');
  assert.equal(joined[0]?.triageState, 'active');
  assert.equal(joined[1]?.triageState, 'mitigated');
});

test('filter by triage state supports active-only, hide-mitigated, and exact-state filters', () => {
  const filterByTriageState = new FilterByTriageState();
  const items = [
    { key: 'a', triageState: 'active' as const },
    { key: 'b', triageState: 'mitigated' as const },
    { key: 'c', triageState: 'suppressed' as const },
    { key: 'd', triageState: 'investigating' as const }
  ];

  assert.deepEqual(filterByTriageState.execute(items, 'active-only').map((item) => item.key), ['a', 'd']);
  assert.deepEqual(filterByTriageState.execute(items, 'hide-mitigated').map((item) => item.key), ['a', 'c', 'd']);
  assert.deepEqual(filterByTriageState.execute(items, 'suppressed').map((item) => item.key), ['c']);
});
