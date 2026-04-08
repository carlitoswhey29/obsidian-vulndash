import test from 'node:test';
import assert from 'node:assert/strict';
import { logger, redactSensitive, redactSensitiveString } from '../../../src/infrastructure/utils/logger';

test('redacts sensitive keys recursively from structured payloads', () => {
  const redacted = redactSensitive({
    token: 'ghp_abcdefghijklmnopqrstuvwxyz123456',
    nested: {
      apiKey: 'nvd-secret-key',
      Authorization: 'Bearer github_pat_abcdefghijklmnopqrstuvwxyz123456',
      safe: 'visible'
    },
    list: [{ 'x-api-key': 'secret-value' }]
  });

  assert.deepEqual(redacted, {
    token: '[REDACTED]',
    nested: {
      apiKey: '[REDACTED]',
      Authorization: '[REDACTED]',
      safe: 'visible'
    },
    list: [{ 'x-api-key': '[REDACTED]' }]
  });
});

test('redacts sensitive substrings in strings', () => {
  const redacted = redactSensitiveString(
    'GET https://example.test/feed?apiKey=abc123&safe=true Authorization: Bearer github_pat_abcdefghijklmnopqrstuvwxyz123456'
  );

  assert.equal(
    redacted,
    'GET https://example.test/feed?apiKey=[REDACTED]&safe=true Authorization: [REDACTED]'
  );
});

test('logger redacts before writing to console', () => {
  const originalInfo = console.info;
  const calls: unknown[][] = [];
  console.info = (...args: unknown[]) => {
    calls.push(args);
  };

  try {
    logger.info('[test]', {
      authorization: 'Bearer ghp_abcdefghijklmnopqrstuvwxyz123456',
      url: 'https://example.test?token=secret-token'
    });
  } finally {
    console.info = originalInfo;
  }

  assert.deepEqual(calls, [[
    '[test]',
    {
      authorization: '[REDACTED]',
      url: 'https://example.test?token=[REDACTED]'
    }
  ]]);
});

