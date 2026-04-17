import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomComparisonService } from '../../../src/application/use-cases/SbomComparisonService';

const comparisonService = new SbomComparisonService();

test('compares normalized SBOM component lists and identifies overlap', () => {
  const result = comparisonService.compare(
    ['Platform Api', 'Portal Web'],
    ['Platform Api', 'Gateway Service']
  );

  assert.deepEqual(result.onlyInA, ['Portal Web']);
  assert.deepEqual(result.onlyInB, ['Gateway Service']);
  assert.deepEqual(result.inBoth, ['Platform Api']);
});

test('deduplicates and trims comparison inputs', () => {
  const result = comparisonService.compare(
    [' Platform Api ', 'Platform Api', 'Portal Web'],
    ['Portal Web', 'Portal Web', 'Gateway Service']
  );

  assert.deepEqual(result.onlyInA, ['Platform Api']);
  assert.deepEqual(result.onlyInB, ['Gateway Service']);
  assert.deepEqual(result.inBoth, ['Portal Web']);
});
