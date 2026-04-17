export interface SbomComparisonResult {
  inBoth: string[];
  onlyInA: string[];
  onlyInB: string[];
}

export class SbomComparisonService {
  public compare(left: string[], right: string[]): SbomComparisonResult {
    const leftValues = this.normalize(left);
    const rightValues = this.normalize(right);
    const leftSet = new Set(leftValues);
    const rightSet = new Set(rightValues);

    return {
      inBoth: leftValues.filter((value) => rightSet.has(value)),
      onlyInA: leftValues.filter((value) => !rightSet.has(value)),
      onlyInB: rightValues.filter((value) => !leftSet.has(value))
    };
  }

  private normalize(values: string[]): string[] {
    return Array.from(new Set(values
      .map((value) => value.trim())
      .filter((value) => value.length > 0)))
      .sort((left, right) => left.localeCompare(right));
  }
}
