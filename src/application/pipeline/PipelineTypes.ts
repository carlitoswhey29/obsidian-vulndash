import type { FeedSyncMode } from '../ports/VulnerabilityFeed';
import type { Vulnerability } from '../../domain/entities/Vulnerability';

export type PipelineRunId = string & { readonly __pipelineRunId: unique symbol };

export interface PipelineBatchInput {
  readonly batchIndex: number;
  readonly sourceId: string;
  readonly sourceName: string;
  readonly totalFetchedItems: number;
  readonly vulnerabilities: readonly Vulnerability[];
}

export interface NormalizedVulnerabilityBatch {
  readonly batchIndex: number;
  readonly normalizedCount: number;
  readonly sourceId: string;
  readonly sourceName: string;
  readonly totalFetchedItems: number;
  readonly vulnerabilities: readonly Vulnerability[];
}

export interface ChangedVulnerabilityIds {
  /**
   * Stable cache keys in the form `${source}:${id}`.
   */
  readonly added: readonly string[];
  readonly updated: readonly string[];
  readonly removed: readonly string[];
}

export interface PipelineMergeResult {
  readonly cacheSize: number;
  readonly changedIds: ChangedVulnerabilityIds;
  readonly itemsDeduplicated: number;
  readonly itemsMerged: number;
}

export interface PipelineProgressEvent {
  readonly batchIndex: number;
  readonly processedItems: number;
  readonly runId: PipelineRunId;
  readonly sourceId: string;
  readonly sourceName: string;
  readonly totalItems: number;
}

export interface PipelineConfig {
  readonly chunkSize: number;
}

export interface PipelineSourceContext {
  readonly existingCursor?: string;
  readonly runId: PipelineRunId;
  readonly since?: string;
  readonly sourceId: string;
  readonly sourceName: string;
  readonly syncMode: FeedSyncMode;
  readonly until: string;
}

export interface PipelineSnapshot {
  readonly cacheByKey: ReadonlyMap<string, Vulnerability>;
  readonly originByKey: ReadonlyMap<string, string>;
}

export const DEFAULT_PIPELINE_CONFIG: PipelineConfig = {
  chunkSize: 100
};

export const createEmptyChangedVulnerabilityIds = (): ChangedVulnerabilityIds => ({
  added: [],
  removed: [],
  updated: []
});

export const buildVulnerabilityCacheKey = (vulnerability: Pick<Vulnerability, 'id' | 'source'>): string =>
  `${vulnerability.source}:${vulnerability.id}`;

export const compareChangeKeys = (left: string, right: string): number =>
  left.localeCompare(right);

export const compareVulnerabilitiesDeterministically = (left: Vulnerability, right: Vulnerability): number =>
  right.publishedAt.localeCompare(left.publishedAt)
  || right.updatedAt.localeCompare(left.updatedAt)
  || left.source.localeCompare(right.source)
  || left.id.localeCompare(right.id)
  || left.title.localeCompare(right.title);

export const compareVulnerabilitiesByFreshness = (left: Vulnerability, right: Vulnerability): number =>
  left.updatedAt.localeCompare(right.updatedAt)
  || left.publishedAt.localeCompare(right.publishedAt)
  || left.source.localeCompare(right.source)
  || left.id.localeCompare(right.id)
  || left.title.localeCompare(right.title);

export const sortVulnerabilitiesDeterministically = (vulnerabilities: Iterable<Vulnerability>): Vulnerability[] =>
  Array.from(vulnerabilities).sort(compareVulnerabilitiesDeterministically);

export const toSortedChangedVulnerabilityIds = (values: {
  added?: Iterable<string>;
  removed?: Iterable<string>;
  updated?: Iterable<string>;
}): ChangedVulnerabilityIds => ({
  added: Array.from(values.added ?? []).sort(compareChangeKeys),
  removed: Array.from(values.removed ?? []).sort(compareChangeKeys),
  updated: Array.from(values.updated ?? []).sort(compareChangeKeys)
});
