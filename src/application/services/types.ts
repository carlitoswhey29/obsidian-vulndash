import type { Severity } from '../../domain/entities/Severity';

export type DashboardSortOrder = 'publishedAt' | 'cvssScore';

export interface ColumnVisibility {
  id: boolean;
  title: boolean;
  source: boolean;
  severity: boolean;
  cvssScore: boolean;
  publishedAt: boolean;
}

export interface VulnDashSettings {
  pollingIntervalMs: number;
  keywordFilters: string[];
  productFilters: string[];
  minSeverity: Severity;
  minCvssScore: number;
  nvdApiKey: string;
  githubToken: string;
  systemNotificationsEnabled: boolean;
  desktopAlertsHighOrCritical: boolean;
  cacheDurationMs: number;
  maxResults: number;
  defaultSortOrder: DashboardSortOrder;
  colorCodedSeverity: boolean;
  columnVisibility: ColumnVisibility;
  keywordRegexEnabled: boolean;
  enableNvdFeed: boolean;
  enableGithubFeed: boolean;
  autoNoteCreationEnabled: boolean;
  autoNoteFolder: string;
  sbomPath: string;
}
