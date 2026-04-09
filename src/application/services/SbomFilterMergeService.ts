import type { ImportedSbomComponent, ImportedSbomConfig, VulnDashSettings } from './types';

type SbomFilterSettings = Pick<VulnDashSettings, 'manualProductFilters' | 'sbomAutoApplyFilters' | 'sbomImportMode' | 'sboms'>;

export class SbomFilterMergeService {
  public merge(settings: SbomFilterSettings): string[] {
    const manualFilters = this.normalizeFilters(settings.manualProductFilters);
    if (!settings.sbomAutoApplyFilters) {
      return manualFilters;
    }

    const importedFilters = this.normalizeFilters(settings.sboms.flatMap((sbom) => this.getSbomFilters(sbom)));
    if (settings.sbomImportMode === 'replace') {
      return importedFilters;
    }

    return this.normalizeFilters([...manualFilters, ...importedFilters]);
  }

  private getSbomFilters(sbom: ImportedSbomConfig): string[] {
    if (!sbom.enabled) {
      return [];
    }

    return sbom.components
      .filter((component) => component.enabled && !component.excluded)
      .map((component) => this.getComponentFilterName(component));
  }

  private getComponentFilterName(component: ImportedSbomComponent): string {
    return component.normalizedName.trim() || component.name.trim();
  }

  private normalizeFilters(filters: string[]): string[] {
    return Array.from(new Set(filters
      .map((filter) => filter.trim())
      .filter((filter) => filter.length > 0)))
      .sort((left, right) => left.localeCompare(right));
  }
}
