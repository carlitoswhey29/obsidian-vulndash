import test from 'node:test';
import assert from 'node:assert/strict';
import { extractNextLink } from './GitHubAdvisoryClient';

test('extractNextLink parses GitHub Link header', () => {
  const link = '<https://api.github.com/advisories?page=2>; rel="next", <https://api.github.com/advisories?page=4>; rel="last"';
  assert.equal(extractNextLink(link), 'https://api.github.com/advisories?page=2');
});

test('extractNextLink returns undefined when next relation is missing', () => {
  const link = '<https://api.github.com/advisories?page=4>; rel="last"';
  assert.equal(extractNextLink(link), undefined);
});
