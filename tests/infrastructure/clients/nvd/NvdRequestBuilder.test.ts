import test from 'node:test';
import assert from 'node:assert/strict';
import { NvdRequestBuilder } from '../../../../src/infrastructure/clients/nvd/NvdRequestBuilder';

test('builds NVD fetch requests with validated params and apiKey headers', () => {
  const builder = new NvdRequestBuilder(' secret-key ');
  const request = builder.buildFetchRequest({
    since: '2026-04-15T00:00:00.000Z',
    until: '2026-04-15T01:00:00.000Z',
    startIndex: 200
  });

  assert.match(request.url, /^https:\/\/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?/);
  assert.match(request.url, /resultsPerPage=100/);
  assert.match(request.url, /startIndex=200/);
  assert.match(request.url, /lastModStartDate=2026-04-15T00%3A00%3A00.000Z/);
  assert.match(request.url, /lastModEndDate=2026-04-15T01%3A00%3A00.000Z/);
  assert.doesNotMatch(request.url, /apiKey=/);
  assert.deepEqual(request.headers, { apiKey: 'secret-key' });
});

test('omits optional NVD fetch request fields when absent', () => {
  const builder = new NvdRequestBuilder();
  const request = builder.buildFetchRequest({ startIndex: 0 });

  assert.match(request.url, /resultsPerPage=100/);
  assert.match(request.url, /startIndex=0/);
  assert.doesNotMatch(request.url, /lastModStartDate=/);
  assert.doesNotMatch(request.url, /lastModEndDate=/);
  assert.deepEqual(request.headers, {});
});

test('builds NVD fetch requests with explicit published-date params', () => {
  const builder = new NvdRequestBuilder();
  const request = builder.buildFetchRequest({
    startIndex: 0,
    publishedFrom: '2026-04-20T00:00:00.000Z',
    publishedUntil: '2026-04-20T23:59:59.999Z'
  });

  assert.match(request.url, /pubStartDate=2026-04-20T00%3A00%3A00.000Z/);
  assert.match(request.url, /pubEndDate=2026-04-20T23%3A59%3A59.999Z/);
});

test('builds NVD validation requests without date filters and keeps apiKey in headers', () => {
  const builder = new NvdRequestBuilder('secret-key');
  const request = builder.buildValidationRequest();

  assert.match(request.url, /resultsPerPage=100/);
  assert.match(request.url, /startIndex=0/);
  assert.doesNotMatch(request.url, /lastModStartDate=/);
  assert.doesNotMatch(request.url, /lastModEndDate=/);
  assert.doesNotMatch(request.url, /apiKey=/);
  assert.deepEqual(request.headers, { apiKey: 'secret-key' });
});
