import type { Severity } from '../../domain/entities/Severity';

export interface VulnDashSettings {
  pollingIntervalMs: number;
  keywordFilters: string[];
  productFilters: string[];
  minSeverity: Severity;
  minCvssScore: number;
  nvdApiKey: string;
  githubToken: string;
}
