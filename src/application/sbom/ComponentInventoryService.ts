import type { SbomLoadResult } from '../services/SbomImportService';
import type { VulnDashSettings } from '../services/types';
import { ComponentPreferenceService } from './ComponentPreferenceService';
import { SbomCatalogService } from './SbomCatalogService';
import type {
  ComponentInventoryIssue,
  ComponentInventorySnapshot
} from './types';

type ComponentInventorySettings = Pick<
  VulnDashSettings,
  'disabledSbomComponentKeys' | 'followedSbomComponentKeys' | 'sboms'
>;

const compareIssues = (
  left: ComponentInventoryIssue,
  right: ComponentInventoryIssue
): number =>
  left.title.localeCompare(right.title)
  || (left.sourcePath ?? '').localeCompare(right.sourcePath ?? '')
  || left.sbomId.localeCompare(right.sbomId);

export class ComponentInventoryService {
  public constructor(
    private readonly catalogService = new SbomCatalogService(),
    private readonly preferenceService = new ComponentPreferenceService()
  ) {}

  public buildSnapshot(
    settings: ComponentInventorySettings,
    loadResults: readonly SbomLoadResult[]
  ): ComponentInventorySnapshot {
    const catalog = this.preferenceService.applyPreferences(
      this.catalogService.buildCatalog(this.collectDocuments(loadResults)),
      settings
    );
    const issues = this.collectIssues(settings, loadResults);

    return {
      catalog,
      configuredSbomCount: settings.sboms.length,
      enabledSbomCount: settings.sboms.filter((sbom) => sbom.enabled).length,
      failedSbomCount: issues.length,
      issues,
      parsedSbomCount: loadResults.filter((result) => result.success || result.cachedState).length
    };
  }

  private collectDocuments(results: readonly SbomLoadResult[]) {
    return results.flatMap((result) => {
      if (result.success) {
        return [result.state.document];
      }

      return result.cachedState ? [result.cachedState.document] : [];
    });
  }

  private collectIssues(
    settings: ComponentInventorySettings,
    results: readonly SbomLoadResult[]
  ): ComponentInventoryIssue[] {
    const settingsById = new Map(settings.sboms.map((sbom) => [sbom.id, sbom] as const));

    return results.flatMap((result) => {
      if (result.success) {
        return [];
      }

      const sbom = settingsById.get(result.sbomId);
      if (!sbom) {
        return [];
      }

      const issue: ComponentInventoryIssue = {
        hasCachedData: result.cachedState !== null,
        message: result.error,
        sbomId: sbom.id,
        title: sbom.label || 'Untitled SBOM'
      };

      const sourcePath = sbom.path.trim();
      if (sourcePath) {
        issue.sourcePath = sourcePath;
      }

      return [issue];
    }).sort(compareIssues);
  }
}
