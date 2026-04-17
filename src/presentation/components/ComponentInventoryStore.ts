import type {
  NormalizedSbomFormat,
  NormalizedSeverity
} from '../../domain/sbom/types';
import type {
  ComponentInventoryWorkspaceSnapshot,
  RelatedVulnerabilitySummary,
  TrackedComponent
} from '../../application/sbom/types';

export type ComponentSeverityFilter = 'any' | NormalizedSeverity;

export interface ComponentInventoryFilters {
  enabledOnly: boolean;
  followedOnly: boolean;
  searchQuery: string;
  sourceFile: string;
  sourceFormat: 'all' | NormalizedSbomFormat;
  severityThreshold: ComponentSeverityFilter;
  vulnerableOnly: boolean;
}

export interface ComponentInventorySummary {
  enabledCount: number;
  followedCount: number;
  totalCount: number;
  vulnerableCount: number;
}

export interface ComponentInventoryDerivedState {
  availableSourceFiles: string[];
  components: ComponentInventoryDisplayEntry[];
  hasActiveFilters: boolean;
  summary: ComponentInventorySummary;
}

export interface ComponentInventoryDisplayEntry {
  component: TrackedComponent;
  highestSeverity: NormalizedSeverity | undefined;
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[];
  vulnerabilityCount: number;
}

const severityOrder: Record<NormalizedSeverity, number> = {
  critical: 5,
  high: 4,
  informational: 1,
  low: 2,
  medium: 3
};

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const severityFromRelatedVulnerability = (
  vulnerability: RelatedVulnerabilitySummary
): NormalizedSeverity | undefined => {
  switch (normalizeToken(vulnerability.severity)) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'informational':
    case 'info':
      return 'informational';
    default:
      return undefined;
  }
};

const pickHigherSeverity = (
  left: NormalizedSeverity | undefined,
  right: NormalizedSeverity | undefined
): NormalizedSeverity | undefined => {
  if (!left) {
    return right;
  }

  if (!right) {
    return left;
  }

  return severityOrder[left] >= severityOrder[right] ? left : right;
};

const getUniqueVulnerabilityCount = (
  component: TrackedComponent,
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[]
): number => {
  const identifiers = new Set<string>();

  for (const vulnerability of component.vulnerabilities) {
    identifiers.add(normalizeToken(vulnerability.id));
  }

  for (const vulnerability of relatedVulnerabilities) {
    identifiers.add(normalizeToken(vulnerability.id));
  }

  return Array.from(identifiers).filter(Boolean).length;
};

const getEffectiveHighestSeverity = (
  component: TrackedComponent,
  relatedVulnerabilities: readonly RelatedVulnerabilitySummary[]
): NormalizedSeverity | undefined =>
  relatedVulnerabilities.reduce<NormalizedSeverity | undefined>(
    (highest, vulnerability) => pickHigherSeverity(highest, severityFromRelatedVulnerability(vulnerability)),
    component.highestSeverity
  );

const toDisplayEntry = (
  snapshot: ComponentInventoryWorkspaceSnapshot,
  component: TrackedComponent
): ComponentInventoryDisplayEntry => {
  const relatedVulnerabilities = snapshot.relationships.vulnerabilitiesByComponent.get(component.key) ?? [];

  return {
    component,
    highestSeverity: getEffectiveHighestSeverity(component, relatedVulnerabilities),
    relatedVulnerabilities,
    vulnerabilityCount: getUniqueVulnerabilityCount(component, relatedVulnerabilities)
  };
};

const buildSearchHaystack = (entry: ComponentInventoryDisplayEntry): string =>
  [
    entry.component.name,
    entry.component.version,
    entry.component.supplier,
    entry.component.license,
    entry.component.purl,
    entry.component.cpe,
    entry.component.key,
    entry.component.notePath ?? '',
    ...entry.component.sourceFiles,
    ...entry.component.formats,
    ...entry.component.vulnerabilities.map((vulnerability) => vulnerability.id),
    ...entry.component.cweGroups.map((group) => `cwe-${group.cwe}`),
    ...entry.relatedVulnerabilities.flatMap((vulnerability) => [
      vulnerability.id,
      vulnerability.source,
      vulnerability.title
    ])
  ].join(' ').toLowerCase();

const matchesSeverityThreshold = (
  entry: ComponentInventoryDisplayEntry,
  threshold: ComponentSeverityFilter
): boolean => {
  if (threshold === 'any') {
    return true;
  }

  const highestSeverity = entry.highestSeverity;
  if (!highestSeverity) {
    return false;
  }

  return severityOrder[highestSeverity] >= severityOrder[threshold];
};

export const createDefaultComponentInventoryFilters = (): ComponentInventoryFilters => ({
  enabledOnly: false,
  followedOnly: false,
  searchQuery: '',
  severityThreshold: 'any',
  sourceFile: 'all',
  sourceFormat: 'all',
  vulnerableOnly: false
});

export const summarizeComponentInventory = (
  components: readonly ComponentInventoryDisplayEntry[]
): ComponentInventorySummary =>
  components.reduce<ComponentInventorySummary>((summary, component) => ({
    enabledCount: summary.enabledCount + (component.component.isEnabled ? 1 : 0),
    followedCount: summary.followedCount + (component.component.isFollowed ? 1 : 0),
    totalCount: summary.totalCount + 1,
    vulnerableCount: summary.vulnerableCount + (component.vulnerabilityCount > 0 ? 1 : 0)
  }), {
    enabledCount: 0,
    followedCount: 0,
    totalCount: 0,
    vulnerableCount: 0
  });

export const filterTrackedComponents = (
  components: readonly ComponentInventoryDisplayEntry[],
  filters: ComponentInventoryFilters
): ComponentInventoryDisplayEntry[] => {
  const normalizedQueryTokens = normalizeToken(filters.searchQuery)
    .split(' ')
    .filter(Boolean);

  return components.filter((component) => {
    if (filters.followedOnly && !component.component.isFollowed) {
      return false;
    }

    if (filters.enabledOnly && !component.component.isEnabled) {
      return false;
    }

    if (filters.vulnerableOnly && component.vulnerabilityCount === 0) {
      return false;
    }

    if (!matchesSeverityThreshold(component, filters.severityThreshold)) {
      return false;
    }

    if (filters.sourceFormat !== 'all' && !component.component.formats.includes(filters.sourceFormat)) {
      return false;
    }

    if (filters.sourceFile !== 'all' && !component.component.sourceFiles.includes(filters.sourceFile)) {
      return false;
    }

    if (normalizedQueryTokens.length > 0) {
      const haystack = buildSearchHaystack(component);
      if (!normalizedQueryTokens.every((token) => haystack.includes(token))) {
        return false;
      }
    }

    return true;
  });
};

export const deriveComponentInventoryState = (
  snapshot: ComponentInventoryWorkspaceSnapshot,
  filters: ComponentInventoryFilters
): ComponentInventoryDerivedState => ({
  availableSourceFiles: snapshot.inventory.catalog.sourceFiles,
  components: filterTrackedComponents(snapshot.inventory.catalog.components.map((component) => toDisplayEntry(snapshot, component)), filters),
  hasActiveFilters: hasActiveComponentInventoryFilters(filters),
  summary: summarizeComponentInventory(snapshot.inventory.catalog.components.map((component) => toDisplayEntry(snapshot, component)))
});

export const hasActiveComponentInventoryFilters = (
  filters: ComponentInventoryFilters
): boolean =>
  filters.enabledOnly
  || filters.followedOnly
  || filters.vulnerableOnly
  || filters.severityThreshold !== 'any'
  || filters.sourceFormat !== 'all'
  || filters.sourceFile !== 'all'
  || normalizeToken(filters.searchQuery).length > 0;
