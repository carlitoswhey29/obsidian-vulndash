export interface NvdCvssMetric {
  cvssData?: { baseScore?: number };
}

export interface NvdCpeMatch {
  criteria?: string;
  vulnerable?: boolean;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

export interface NvdConfigurationNode {
  cpeMatch?: NvdCpeMatch[];
  nodes?: NvdConfigurationNode[];
}

export interface NvdCveRecord {
  id?: string;
  published?: string;
  lastModified?: string;
  descriptions?: Array<{ lang?: string; value?: string }>;
  references?: Array<{ url?: string }>;
  weaknesses?: Array<{ description?: Array<{ lang?: string; value?: string }> }>;
  metrics?: {
    cvssMetricV31?: NvdCvssMetric[];
    cvssMetricV30?: NvdCvssMetric[];
    cvssMetricV2?: NvdCvssMetric[];
  };
  configurations?: Array<{ nodes?: NvdConfigurationNode[] }>;
}

export interface NvdResponse {
  startIndex?: number;
  resultsPerPage?: number;
  totalResults?: number;
  vulnerabilities?: Array<{
    cve?: NvdCveRecord;
  }>;
}

export interface ParsedCpe {
  vendor: string;
  product: string;
  version: string;
}
