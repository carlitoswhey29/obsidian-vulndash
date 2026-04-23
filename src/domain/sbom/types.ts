export type NormalizedSbomFormat = 'cyclonedx' | 'spdx';

export type NormalizedSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'informational';

export interface NormalizedComponentVulnerabilitySummary {
  cweIds: number[];
  highestSeverity?: NormalizedSeverity;
  severities: NormalizedSeverity[];
  vulnerabilityCount: number;
  vulnerabilityIds: string[];
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
  id: string;
  name: string;
  notePath?: string | null;
  vulnerabilitySummary: NormalizedComponentVulnerabilitySummary;
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
