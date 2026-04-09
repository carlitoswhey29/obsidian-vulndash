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

export interface SyncControls {
  maxPages: number;
  maxItems: number;
  retryCount: number;
  backoffBaseMs: number;
  overlapWindowMs: number;
  bootstrapLookbackMs: number;
  debugHttpMetadata: boolean;
}

export type FeedConfigType = 'nvd' | 'github_advisory' | 'github_repo' | 'generic_json';

interface FeedConfigBase {
  id: string;
  name: string;
  enabled: boolean;
  token?: string;
}

export interface NvdFeedConfig extends FeedConfigBase {
  type: 'nvd';
  apiKey?: string;
}

export interface GitHubAdvisoryFeedConfig extends FeedConfigBase {
  type: 'github_advisory';
}

export interface GitHubRepoFeedConfig extends FeedConfigBase {
  type: 'github_repo';
  repoPath: string;
}

export interface GenericJsonFeedConfig extends FeedConfigBase {
  type: 'generic_json';
  url: string;
  authHeaderName?: string;
}

export type FeedConfig =
  | NvdFeedConfig
  | GitHubAdvisoryFeedConfig
  | GitHubRepoFeedConfig
  | GenericJsonFeedConfig;

export interface ImportedSbomComponent {
  id: string;
  name: string;
  normalizedName: string;
  version: string;
  purl: string;
  cpe: string;
  bomRef: string;
  namespace: string;
  enabled: boolean;
  excluded: boolean;
}

export interface ImportedSbomConfig {
  id: string;
  label: string;
  path: string;
  namespace: string;
  enabled: boolean;
  components: ImportedSbomComponent[];
  lastImportedAt: number | null;
  lastImportHash: string | null;
  lastImportError: string | null;
}

export interface VulnDashSettings {
  pollingIntervalMs: number;
  pollOnStartup: boolean;
  keywordFilters: string[];
  manualProductFilters: string[];
  /**
   * Computed filter output. Manual edits should target `manualProductFilters`.
   */
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
  autoHighNoteCreationEnabled: boolean;
  autoNoteFolder: string;
  sboms: ImportedSbomConfig[];
  sbomImportMode: 'replace' | 'append';
  sbomAutoApplyFilters: boolean;
  /**
   * Legacy-only migration field. New logic must rely on `sboms`.
   */
  sbomPath: string;
  syncControls: SyncControls;
  sourceSyncCursor: Record<string, string>;
  settingsVersion: number;
  feeds: FeedConfig[];
}
