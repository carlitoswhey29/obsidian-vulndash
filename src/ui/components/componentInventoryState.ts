import type {
  NormalizedSbomFormat,
  NormalizedSeverity
} from '../../domain/sbom/types';
import type {
  ComponentInventorySnapshot,
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
  components: TrackedComponent[];
  hasActiveFilters: boolean;
  summary: ComponentInventorySummary;
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

const buildSearchHaystack = (component: TrackedComponent): string =>
  [
    component.name,
    component.version,
    component.supplier,
    component.license,
    component.purl,
    component.cpe,
    component.key,
    component.notePath ?? '',
    ...component.sourceFiles,
    ...component.formats,
    ...component.vulnerabilities.map((vulnerability) => vulnerability.id),
    ...component.cweGroups.map((group) => `cwe-${group.cwe}`)
  ].join(' ').toLowerCase();

const matchesSeverityThreshold = (
  component: TrackedComponent,
  threshold: ComponentSeverityFilter
): boolean => {
  if (threshold === 'any') {
    return true;
  }

  const highestSeverity = component.highestSeverity;
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
  components: readonly TrackedComponent[]
): ComponentInventorySummary =>
  components.reduce<ComponentInventorySummary>((summary, component) => ({
    enabledCount: summary.enabledCount + (component.isEnabled ? 1 : 0),
    followedCount: summary.followedCount + (component.isFollowed ? 1 : 0),
    totalCount: summary.totalCount + 1,
    vulnerableCount: summary.vulnerableCount + (component.vulnerabilityCount > 0 ? 1 : 0)
  }), {
    enabledCount: 0,
    followedCount: 0,
    totalCount: 0,
    vulnerableCount: 0
  });

export const filterTrackedComponents = (
  components: readonly TrackedComponent[],
  filters: ComponentInventoryFilters
): TrackedComponent[] => {
  const normalizedQuery = normalizeToken(filters.searchQuery);

  return components.filter((component) => {
    if (filters.followedOnly && !component.isFollowed) {
      return false;
    }

    if (filters.enabledOnly && !component.isEnabled) {
      return false;
    }

    if (filters.vulnerableOnly && component.vulnerabilityCount === 0) {
      return false;
    }

    if (!matchesSeverityThreshold(component, filters.severityThreshold)) {
      return false;
    }

    if (filters.sourceFormat !== 'all' && !component.formats.includes(filters.sourceFormat)) {
      return false;
    }

    if (filters.sourceFile !== 'all' && !component.sourceFiles.includes(filters.sourceFile)) {
      return false;
    }

    if (normalizedQuery && !buildSearchHaystack(component).includes(normalizedQuery)) {
      return false;
    }

    return true;
  });
};

export const deriveComponentInventoryState = (
  snapshot: ComponentInventorySnapshot,
  filters: ComponentInventoryFilters
): ComponentInventoryDerivedState => ({
  availableSourceFiles: snapshot.catalog.sourceFiles,
  components: filterTrackedComponents(snapshot.catalog.components, filters),
  hasActiveFilters: hasActiveComponentInventoryFilters(filters),
  summary: summarizeComponentInventory(snapshot.catalog.components)
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
