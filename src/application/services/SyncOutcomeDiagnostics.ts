import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { SyncResult } from './PollingOrchestrator';

export interface FeedSyncSummary {
  feedId: string;
  source: string;
  success: boolean;
  pagesFetched: number;
  itemsFetched: number;
  warnings: string[];
  errorSummary?: string;
  authFailure?: {
    reason: 'unauthorized' | 'forbidden';
  };
}

export interface VisibilityDiagnostics {
  totalFetched: number;
  totalVisible: number;
  filteredOut: number;
  fetchedBySource: Record<string, number>;
  visibleBySource: Record<string, number>;
}

const countBySource = (vulnerabilities: Vulnerability[]): Record<string, number> => {
  return vulnerabilities.reduce<Record<string, number>>((counts, vulnerability) => {
    counts[vulnerability.source] = (counts[vulnerability.source] ?? 0) + 1;
    return counts;
  }, {});
};

export const summarizeSyncResults = (results: SyncResult[]): FeedSyncSummary[] => {
  return results.map((result) => ({
    feedId: result.feedId,
    source: result.source,
    success: result.success,
    pagesFetched: result.pagesFetched,
    itemsFetched: result.itemsFetched,
    warnings: [...result.warnings],
    ...(result.errorSummary ? { errorSummary: result.errorSummary } : {}),
    ...(result.authFailure ? { authFailure: result.authFailure } : {})
  }));
};

export const getFailedFeedNames = (results: SyncResult[]): string[] => {
  return results.filter((result) => !result.success).map((result) => result.source);
};

export const buildFailureNoticeMessage = (results: SyncResult[]): string | undefined => {
  const authFailures = results.filter((result) => result.authFailure);
  if (authFailures.length > 0) {
    return `VulnDash authentication failed for: ${authFailures.map((result) => result.source).join(', ')}. Token or API key may be expired, revoked, invalid, or missing required permissions.`;
  }

  const failed = getFailedFeedNames(results);
  if (failed.length === 0) return undefined;
  return `VulnDash sync failed for: ${failed.join(', ')}. Check logs for details.`;
};

export const buildVisibilityDiagnostics = (
  vulnerabilities: Vulnerability[],
  visibleVulnerabilities: Vulnerability[]
): VisibilityDiagnostics => {
  return {
    totalFetched: vulnerabilities.length,
    totalVisible: visibleVulnerabilities.length,
    filteredOut: vulnerabilities.length - visibleVulnerabilities.length,
    fetchedBySource: countBySource(vulnerabilities),
    visibleBySource: countBySource(visibleVulnerabilities)
  };
};
