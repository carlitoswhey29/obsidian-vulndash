import type { TrackedComponent } from '../../application/sbom/types';

const normalizeComponentKey = (value: string): string =>
  value.trim().toLowerCase();

export class SbomComponentIndex {
  public build(
    components: readonly TrackedComponent[],
    sbomIdsBySourcePath: ReadonlyMap<string, readonly string[]>
  ): BuiltSbomComponentIndex {
    const sbomIdsByComponentKey = new Map<string, string[]>();

    for (const component of components) {
      const matchedSbomIds = new Set<string>();

      for (const source of component.sources) {
        const sourceSbomIds = sbomIdsBySourcePath.get(source.sourcePath) ?? [];
        for (const sbomId of sourceSbomIds) {
          matchedSbomIds.add(sbomId);
        }
      }

      const normalizedComponentKey = normalizeComponentKey(component.key);
      sbomIdsByComponentKey.set(
        normalizedComponentKey,
        Array.from(matchedSbomIds).sort((left, right) => left.localeCompare(right))
      );
    }

    return new BuiltSbomComponentIndex(sbomIdsByComponentKey);
  }
}

export class BuiltSbomComponentIndex {
  public constructor(
    private readonly sbomIdsByComponentKey: ReadonlyMap<string, readonly string[]>
  ) {}

  public getSbomIdsForComponent(componentKey: string): readonly string[] {
    return this.sbomIdsByComponentKey.get(normalizeComponentKey(componentKey)) ?? [];
  }
}
