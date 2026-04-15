import test from 'node:test';
import assert from 'node:assert/strict';
import {
  NVD_MAX_START_INDEX,
  validateApiKey,
  validateDateRange,
  validateIsoUtcDate,
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

test('validateDateRange rejects inverted ranges', () => {
  assert.throws(
    () => validateDateRange('2026-04-15T02:00:00.000Z', '2026-04-15T01:00:00.000Z'),
    /lastModStartDate must be less than or equal to lastModEndDate/
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
});
