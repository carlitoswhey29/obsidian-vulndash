import assert from 'node:assert/strict';
import test from 'node:test';
import { TriageRecord } from '../../../src/domain/triage/TriageRecord';

test('triage record normalizes timestamps and optional fields while remaining immutable', () => {
  const record = TriageRecord.create({
    correlationKey: 'nvd::cve-2026-0001',
    reason: '  investigated in patch window  ',
    source: 'NVD',
    state: 'mitigated',
    ticketRef: '  SEC-1234 ',
    updatedAt: '2026-04-17T14:30:00Z',
    updatedBy: ' analyst ',
    vulnerabilityId: 'CVE-2026-0001'
  });

  assert.equal(record.updatedAt, '2026-04-17T14:30:00.000Z');
  assert.equal(record.reason, 'investigated in patch window');
  assert.equal(record.ticketRef, 'SEC-1234');
  assert.equal(record.updatedBy, 'analyst');
  assert.equal(Object.isFrozen(record), true);
});

test('triage record rejects missing required fields', () => {
  assert.throws(() => TriageRecord.create({
    correlationKey: ' ',
    source: 'NVD',
    state: 'active',
    updatedAt: '2026-04-17T14:30:00.000Z',
    vulnerabilityId: 'CVE-2026-0001'
  }), /correlationKey/);
});
