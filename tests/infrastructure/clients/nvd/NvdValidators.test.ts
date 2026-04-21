import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NVD_MAX_START_INDEX,
  validateApiKey,
  validateDateRange,
  validateIsoUtcDate,
  validatePublishedDateRange,
  validateStartIndex
} from '../../../../src/infrastructure/clients/nvd/NvdValidators';

test('validateDateRange omits undefined properties', () => {
  const range = validateDateRange(undefined, undefined);

  assert.deepEqual(range, {});
  assert.equal('since' in range, false);
  assert.equal('until' in range, false);
});

test('validateDateRange preserves valid UTC bounds', () => {
  const range = validateDateRange('2026-04-15T00:00:00.000Z', '2026-04-15T01:00:00.000Z');

  assert.deepEqual(range, {
    since: '2026-04-15T00:00:00.000Z',
    until: '2026-04-15T01:00:00.000Z'
  });
});

test('validatePublishedDateRange preserves valid UTC bounds', () => {
  const range = validatePublishedDateRange('2026-04-20T00:00:00.000Z', '2026-04-20T23:59:59.999Z');

  assert.deepEqual(range, {
    publishedFrom: '2026-04-20T00:00:00.000Z',
    publishedUntil: '2026-04-20T23:59:59.999Z'
  });
});

test('validateIsoUtcDate accepts valid UTC timestamps', () => {
  assert.equal(
    validateIsoUtcDate('2026-04-15T00:00:00.000Z', 'lastModStartDate'),
    '2026-04-15T00:00:00.000Z'
  );
});

test('validateDateRange rejects inverted ranges', () => {
  assert.throws(
    () => validateDateRange('2026-04-15T02:00:00.000Z', '2026-04-15T01:00:00.000Z'),
    /lastModStartDate must be less than or equal to lastModEndDate/
  );
});

test('validatePublishedDateRange rejects inverted ranges', () => {
  assert.throws(
    () => validatePublishedDateRange('2026-04-21T00:00:00.000Z', '2026-04-20T23:59:59.999Z'),
    /pubStartDate must be less than or equal to pubEndDate/
  );
});

test('validateIsoUtcDate rejects non-UTC timestamps', () => {
  assert.throws(
    () => validateIsoUtcDate('2026-04-15T00:00:00', 'lastModStartDate'),
    /must be a valid ISO-8601 UTC timestamp/
  );
});

test('validateStartIndex enforces integer bounds', () => {
  assert.equal(validateStartIndex(0), 0);
  assert.equal(validateStartIndex(25), 25);
  assert.throws(() => validateStartIndex(-1), /greater than or equal to 0/);
  assert.throws(() => validateStartIndex(1.5), /must be an integer/);
  assert.throws(
    () => validateStartIndex(NVD_MAX_START_INDEX + 1),
    /exceeds maximum allowed value/
  );
});

test('validateApiKey trims valid input and rejects control characters', () => {
  assert.equal(validateApiKey(' secret-key '), 'secret-key');
  assert.throws(() => validateApiKey('secret\nkey'), /invalid control characters/);
  assert.throws(() => validateApiKey('secret\tkey'), /invalid control characters/);
  assert.throws(() => validateApiKey('secret\u0000key'), /invalid control characters/);
});
