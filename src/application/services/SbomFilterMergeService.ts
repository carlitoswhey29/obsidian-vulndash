import type {
  ImportedSbomConfig,
  ResolvedSbomComponent,
  RuntimeSbomState,
  SbomComponentOverride,
  VulnDashSettings
} from './types';
import { buildSbomOverrideKey } from './types';

type SbomFilterSettings = Pick<VulnDashSettings, 'manualProductFilters' | 'sbomImportMode' | 'sbomOverrides' | 'sboms'>;

export class SbomFilterMergeService {
  public merge(settings: SbomFilterSettings, runtimeCache: Map<string, RuntimeSbomState>): string[] {
    const manualFilters = this.normalizeFilters(settings.manualProductFilters);
    const sbomFilters = this.normalizeFilters(settings.sboms.flatMap((sbom) => {
      const runtimeState = runtimeCache.get(sbom.id) ?? null;
      return this.getResolvedComponents(sbom, runtimeState, settings.sbomOverrides)
        .filter((component) => !component.excluded)
        .map((component) => component.displayName);
    }));

    if (settings.sbomImportMode === 'replace') {
      return sbomFilters;
    }

    return this.normalizeFilters([...manualFilters, ...sbomFilters]);
  }

  public getResolvedComponents(
    sbom: ImportedSbomConfig,
    runtimeState: RuntimeSbomState | null,
    overrides: Record<string, SbomComponentOverride>
  ): ResolvedSbomComponent[] {
    if (!runtimeState) {
      return [];
    }

    return runtimeState.components.map((component) => {
      const override = overrides[buildSbomOverrideKey(sbom.id, component.originalName)];
      const editedName = override?.editedName?.trim() ?? '';
      const displayName = editedName || component.normalizedName.trim() || component.originalName.trim();

      return {
        displayName,
        ...(editedName ? { editedName } : {}),
        excluded: override?.excluded ?? false,
        normalizedName: component.normalizedName.trim() || component.originalName.trim(),
        originalName: component.originalName
      };
    }).sort((left, right) =>
      left.displayName.localeCompare(right.displayName) || left.originalName.localeCompare(right.originalName));
  }

  private normalizeFilters(filters: string[]): string[] {
    return Array.from(new Set(filters
      .map((filter) => filter.trim())
      .filter((filter) => filter.length > 0)))
      .sort((left, right) => left.localeCompare(right));
  }
}
