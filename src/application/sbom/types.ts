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

export interface CatalogComponentInput {
  component: NormalizedComponent;
  document: {
    format: NormalizedSbomFormat;
    name: string;
    sourcePath: string;
  };
}
