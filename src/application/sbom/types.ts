import type {
  NormalizedComponent,
  NormalizedCweGroup,
  NormalizedSbomFormat,
  NormalizedSeverity,
  NormalizedVulnerability
} from '../../domain/sbom/types';

export interface TrackedComponentSource {
  componentId: string;
  documentName: string;
  format: NormalizedSbomFormat;
  name: string;
  sourcePath: string;
  cpe?: string;
  notePath?: string | null;
  purl?: string;
  version?: string;
}

export interface TrackedComponent {
  cweGroups: NormalizedCweGroup[];
  formats: NormalizedSbomFormat[];
  isEnabled: boolean;
  isFollowed: boolean;
  key: string;
  name: string;
  sourceFiles: string[];
  sources: TrackedComponentSource[];
  vulnerabilities: NormalizedVulnerability[];
  vulnerabilityCount: number;
  cpe?: string;
  highestSeverity?: NormalizedSeverity;
  license?: string;
  notePath?: string | null;
  purl?: string;
  supplier?: string;
  version?: string;
}

export interface ComponentCatalog {
  componentCount: number;
  components: TrackedComponent[];
  formats: NormalizedSbomFormat[];
  sourceFiles: string[];
}

export interface ComponentInventoryIssue {
  hasCachedData: boolean;
  message: string;
  sbomId: string;
  sourcePath?: string;
  title: string;
}

export interface ComponentInventorySnapshot {
  catalog: ComponentCatalog;
  configuredSbomCount: number;
  enabledSbomCount: number;
  failedSbomCount: number;
  issues: ComponentInventoryIssue[];
  parsedSbomCount: number;
}

export type ComponentVulnerabilityLinkEvidence = 'cpe' | 'explicit' | 'name-version' | 'purl';

export interface ComponentVulnerabilityRelationship {
  componentKey: string;
  evidence: ComponentVulnerabilityLinkEvidence;
  vulnerabilityId: string;
  vulnerabilityRef: string;
  vulnerabilitySource: string;
}

export interface RelatedComponentSummary {
  evidence: ComponentVulnerabilityLinkEvidence;
  key: string;
  name: string;
  vulnerabilityCount: number;
  cpe?: string;
  highestSeverity?: NormalizedSeverity;
  notePath?: string | null;
  purl?: string;
  version?: string;
}

export interface RelatedVulnerabilitySummary {
  cvssScore: number;
  evidence: ComponentVulnerabilityLinkEvidence;
  id: string;
  referenceCount: number;
  severity: string;
  source: string;
  title: string;
  notePath?: string;
}

export interface ComponentRelationshipGraph {
  componentsByVulnerability: Map<string, RelatedComponentSummary[]>;
  relationships: ComponentVulnerabilityRelationship[];
  vulnerabilitiesByComponent: Map<string, RelatedVulnerabilitySummary[]>;
}

export interface ComponentInventoryWorkspaceSnapshot {
  inventory: ComponentInventorySnapshot;
  relationships: ComponentRelationshipGraph;
}

export interface CatalogComponentInput {
  component: NormalizedComponent;
  document: {
    format: NormalizedSbomFormat;
    name: string;
    sourcePath: string;
  };
}
