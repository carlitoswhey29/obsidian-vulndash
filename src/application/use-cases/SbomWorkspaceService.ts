import type { SbomComparisonResult } from './SbomComparisonService';
import type { SbomFileChangeStatus } from './SbomImportService';
import type { ImportedSbomConfig } from './types';

const PRIMARY_SBOM_KEYWORDS = ['cyclonedx', 'sbom'];
const SECONDARY_SBOM_KEYWORDS = ['bom', 'component', 'components', 'dependency', 'dependencies', 'inventory', 'vex'];

export interface SbomWorkspaceSummary {
  changed: number;
  configured: number;
  enabled: number;
  withErrors: number;
}

export interface SbomStatusDescriptor {
  label: string;
  tone: 'danger' | 'neutral' | 'success' | 'warning';
}

const normalizeSearchQuery = (value: string): string =>
  value.trim().toLowerCase();

const getSearchableSbomText = (sbom: ImportedSbomConfig): string =>
  [
    sbom.label,
    sbom.path,
    sbom.namespace ?? '',
    sbom.lastError ?? ''
  ].join(' ').toLowerCase();

const getPathKeywordScore = (path: string): number => {
  const normalizedPath = path.trim().toLowerCase();
  let score = normalizedPath.endsWith('.json') ? 100 : 0;

  for (const keyword of PRIMARY_SBOM_KEYWORDS) {
    if (normalizedPath.includes(keyword)) {
      score += 50;
    }
  }

  for (const keyword of SECONDARY_SBOM_KEYWORDS) {
    if (normalizedPath.includes(keyword)) {
      score += 15;
    }
  }

  if (normalizedPath.includes('/report') || normalizedPath.includes('/reports')) {
    score += 10;
  }

  return score;
};

export const describeSbomFileStatus = (status?: SbomFileChangeStatus): SbomStatusDescriptor => {
  if (!status) {
    return { label: 'Checking file status', tone: 'neutral' };
  }

  if (status.status === 'error' && status.error === 'SBOM path is required.') {
    return { label: 'No file selected', tone: 'neutral' };
  }

  switch (status.status) {
    case 'changed':
      return { label: 'Changed since last sync', tone: 'warning' };
    case 'missing':
      return { label: 'SBOM file is missing', tone: 'danger' };
    case 'not-imported':
      return { label: 'Ready to import', tone: 'neutral' };
    case 'unchanged':
      return { label: 'Up to date', tone: 'success' };
    case 'error':
    default:
      return { label: status.error ?? 'Unable to inspect SBOM file', tone: 'danger' };
  }
};

export const filterSbomsForWorkspace = (
  sboms: ImportedSbomConfig[],
  query: string
): ImportedSbomConfig[] => {
  const normalizedQuery = normalizeSearchQuery(query);
  if (!normalizedQuery) {
    return sboms;
  }

  return sboms.filter((sbom) => getSearchableSbomText(sbom).includes(normalizedQuery));
};

export const filterSbomComparisonResult = (
  comparison: SbomComparisonResult,
  query: string
): SbomComparisonResult => {
  const normalizedQuery = normalizeSearchQuery(query);
  if (!normalizedQuery) {
    return comparison;
  }

  const filterValues = (values: string[]): string[] =>
    values.filter((value) => value.toLowerCase().includes(normalizedQuery));

  return {
    inBoth: filterValues(comparison.inBoth),
    onlyInA: filterValues(comparison.onlyInA),
    onlyInB: filterValues(comparison.onlyInB)
  };
};

export const isLikelySbomFilePath = (path: string): boolean =>
  path.trim().toLowerCase().endsWith('.json');

export const sortSbomFileCandidates = <T extends { path: string }>(files: T[]): T[] =>
  [...files]
    .filter((file) => isLikelySbomFilePath(file.path))
    .sort((left, right) => {
      const scoreDelta = getPathKeywordScore(right.path) - getPathKeywordScore(left.path);
      if (scoreDelta !== 0) {
        return scoreDelta;
      }

      return left.path.localeCompare(right.path);
    });

export const summarizeSbomWorkspace = (
  sboms: ImportedSbomConfig[],
  statuses = new Map<string, SbomFileChangeStatus>()
): SbomWorkspaceSummary => {
  let changed = 0;
  let withErrors = 0;

  for (const sbom of sboms) {
    const status = statuses.get(sbom.id);
    if (status?.status === 'changed') {
      changed += 1;
    }
    const hasSelectableError = status?.status === 'missing'
      || (status?.status === 'error' && status.error !== 'SBOM path is required.');
    if (sbom.lastError || hasSelectableError) {
      withErrors += 1;
    }
  }

  return {
    changed,
    configured: sboms.length,
    enabled: sboms.filter((sbom) => sbom.enabled).length,
    withErrors
  };
};
