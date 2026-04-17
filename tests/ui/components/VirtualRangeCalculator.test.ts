import assert from 'node:assert/strict';
import test from 'node:test';
import { calculateVirtualRange, createHeightPrefixSums } from '../../../src/ui/components/VirtualRangeCalculator';

test('createHeightPrefixSums accumulates row heights deterministically', () => {
  assert.deepEqual(createHeightPrefixSums([40, 80, 60]), [0, 40, 120, 180]);
});

test('calculateVirtualRange returns an empty range for an empty dataset', () => {
  assert.deepEqual(calculateVirtualRange({
    itemHeights: [],
    overscanItems: 4,
    scrollTop: 0,
    viewportHeight: 300
  }), {
    endIndex: -1,
    offsetBottom: 0,
    offsetTop: 0,
    startIndex: 0,
    totalHeight: 0
  });
});

test('calculateVirtualRange applies overscan around visible fixed-height rows', () => {
  assert.deepEqual(calculateVirtualRange({
    itemHeights: [50, 50, 50, 50, 50],
    overscanItems: 1,
    scrollTop: 0,
    viewportHeight: 100
  }), {
    endIndex: 2,
    offsetBottom: 100,
    offsetTop: 0,
    startIndex: 0,
    totalHeight: 250
  });
});

test('calculateVirtualRange respects variable row heights without rendering hidden rows', () => {
  assert.deepEqual(calculateVirtualRange({
    itemHeights: [40, 80, 60, 120],
    overscanItems: 0,
    scrollTop: 45,
    viewportHeight: 70
  }), {
    endIndex: 1,
    offsetBottom: 180,
    offsetTop: 40,
    startIndex: 1,
    totalHeight: 300
  });
});

test('calculateVirtualRange clamps oversized scroll offsets safely', () => {
  assert.deepEqual(calculateVirtualRange({
    itemHeights: [30, 30],
    overscanItems: 1,
    scrollTop: 500,
    viewportHeight: 40
  }), {
    endIndex: 1,
    offsetBottom: 0,
    offsetTop: 0,
    startIndex: 0,
    totalHeight: 60
  });
});


