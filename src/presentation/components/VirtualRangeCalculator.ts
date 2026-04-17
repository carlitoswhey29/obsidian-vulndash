export interface VirtualRangeInput {
  itemHeights: readonly number[];
  overscanItems: number;
  scrollTop: number;
  viewportHeight: number;
}

export interface VirtualRange {
  endIndex: number;
  offsetBottom: number;
  offsetTop: number;
  startIndex: number;
  totalHeight: number;
}

const clampNumber = (value: number, minimum: number, maximum: number): number =>
  Math.min(Math.max(value, minimum), maximum);

export const createHeightPrefixSums = (itemHeights: readonly number[]): number[] => {
  const prefixSums = new Array<number>(itemHeights.length + 1);
  prefixSums[0] = 0;

  for (let index = 0; index < itemHeights.length; index += 1) {
    const previousHeight = prefixSums[index] ?? 0;
    prefixSums[index + 1] = previousHeight + Math.max(itemHeights[index] ?? 0, 0);
  }

  return prefixSums;
};

const findItemIndexForOffset = (prefixSums: readonly number[], offset: number): number => {
  const itemCount = prefixSums.length - 1;
  const lastIndex = itemCount - 1;
  if (lastIndex < 0) {
    return 0;
  }

  const clampedOffset = clampNumber(offset, 0, prefixSums[itemCount] ?? 0);
  let low = 0;
  let high = lastIndex;

  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const itemTop = prefixSums[middle] ?? 0;
    const itemBottom = prefixSums[middle + 1] ?? itemTop;

    if (clampedOffset < itemTop) {
      high = middle - 1;
      continue;
    }

    if (clampedOffset >= itemBottom) {
      low = middle + 1;
      continue;
    }

    return middle;
  }

  return clampNumber(low, 0, lastIndex);
};

export const calculateVirtualRange = ({
  itemHeights,
  overscanItems,
  scrollTop,
  viewportHeight
}: VirtualRangeInput): VirtualRange => {
  if (itemHeights.length === 0) {
    return {
      endIndex: -1,
      offsetBottom: 0,
      offsetTop: 0,
      startIndex: 0,
      totalHeight: 0
    };
  }

  const prefixSums = createHeightPrefixSums(itemHeights);
  const totalHeight = prefixSums[itemHeights.length] ?? 0;
  const normalizedViewportHeight = Math.max(viewportHeight, 0);
  const viewportBottom = scrollTop + normalizedViewportHeight;
  const visibleStart = findItemIndexForOffset(prefixSums, scrollTop);
  const visibleEnd = findItemIndexForOffset(prefixSums, Math.max(viewportBottom - 1, scrollTop));
  const safeOverscan = Math.max(Math.floor(overscanItems), 0);
  const startIndex = Math.max(visibleStart - safeOverscan, 0);
  const endIndex = Math.min(visibleEnd + safeOverscan, itemHeights.length - 1);
  const offsetTop = prefixSums[startIndex] ?? 0;
  const offsetBottom = totalHeight - (prefixSums[endIndex + 1] ?? totalHeight);

  return {
    endIndex,
    offsetBottom,
    offsetTop,
    startIndex,
    totalHeight
  };
};
