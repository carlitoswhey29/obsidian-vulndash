import type {
  NormalizedSbomDocument,
  NormalizedSeverity
} from '../../domain/sbom/types';
import { ComponentIdentityService } from './ComponentIdentityService';
import { ComponentMergeService } from './ComponentMergeService';
import type { ComponentCatalog, TrackedComponent } from './types';

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const getSeverityRank = (severity: NormalizedSeverity | undefined): number => {
  switch (severity) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    case 'informational':
      return 1;
    default:
      return 0;
  }
};

const compareDocuments = (
  left: NormalizedSbomDocument,
  right: NormalizedSbomDocument
): number =>
  left.sourcePath.localeCompare(right.sourcePath)
  || left.format.localeCompare(right.format)
  || left.name.localeCompare(right.name);

const compareTrackedComponents = (
  left: TrackedComponent,
  right: TrackedComponent
): number => {
  const severityDiff = getSeverityRank(right.highestSeverity) - getSeverityRank(left.highestSeverity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  return normalizeToken(left.name).localeCompare(normalizeToken(right.name))
    || normalizeToken(left.version ?? '').localeCompare(normalizeToken(right.version ?? ''))
    || left.key.localeCompare(right.key);
};

export class SbomCatalogService {
  public constructor(
    private readonly identityService = new ComponentIdentityService(),
    private readonly mergeService = new ComponentMergeService()
  ) {}

  public buildCatalog(documents: Iterable<NormalizedSbomDocument>): ComponentCatalog {
    const sortedDocuments = [...documents].sort(compareDocuments);
    const trackedComponents = new Map<string, TrackedComponent>();
    const sourceFiles = new Set<string>();
    const formats = new Set<NormalizedSbomDocument['format']>();

    for (const document of sortedDocuments) {
      sourceFiles.add(document.sourcePath);
      formats.add(document.format);

      for (const component of document.components) {
        const key = this.identityService.getCanonicalKey(component);
        const tracked = this.mergeService.createTrackedComponent(key, {
          component,
          document
        });
        const existing = trackedComponents.get(key);

        trackedComponents.set(
          key,
          existing ? this.mergeService.mergeComponents(existing, tracked) : tracked
        );
      }
    }

    const components = Array.from(trackedComponents.values()).sort(compareTrackedComponents);

    return {
      componentCount: components.length,
      components,
      formats: Array.from(formats).sort((left, right) => left.localeCompare(right)),
      sourceFiles: Array.from(sourceFiles).sort((left, right) => left.localeCompare(right))
    };
  }
}
