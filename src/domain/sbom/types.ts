export type NormalizedSbomFormat = 'cyclonedx' | 'spdx';

export type NormalizedSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational';

export interface NormalizedDataviewFields {
  vulnerabilityCount: number;
  highestSeverity?: NormalizedSeverity;
  cweList: string[];
  vulnerabilityIds: string[];
  severities: NormalizedSeverity[];
}

export interface NormalizedCweGroup {
  count: number;
  cwe: number;
  vulnerabilityIds: string[];
}

export interface NormalizedVulnerability {
  cwes: number[];
  id: string;
  bomRef?: string;
  description?: string;
  method?: string;
  published?: string;
  score?: number;
  severity?: NormalizedSeverity;
  sourceName?: string;
  sourceUrl?: string;
  updated?: string;
  vector?: string;
}

export interface NormalizedComponent {
  cweGroups: NormalizedCweGroup[];
  dataview: NormalizedDataviewFields;
  id: string;
  name: string;
  notePath?: string | null;
  vulnerabilities: NormalizedVulnerability[];
  vulnerabilityCount: number;
  cpe?: string;
  highestSeverity?: NormalizedSeverity;
  license?: string;
  purl?: string;
  supplier?: string;
  version?: string;
}

export interface NormalizedSbomDocument {
  components: NormalizedComponent[];
  format: NormalizedSbomFormat;
  name: string;
  sourcePath: string;
}
