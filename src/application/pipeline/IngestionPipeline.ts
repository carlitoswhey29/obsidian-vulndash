import {
  AuthFailureHttpError,
  ClientHttpError,
  HttpRequestError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError,
  TimeoutHttpError
} from '../ports/DataSourceError';
import type {
  FetchVulnerabilityBatch,
  FetchVulnerabilityOptions,
  VulnerabilityFeed
} from '../ports/VulnerabilityFeed';
import type { SyncControls } from '../use-cases/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { PipelineEventListener } from './PipelineEvents';
import type {
  ChangedVulnerabilityIds,
  NormalizedVulnerabilityBatch,
  PipelineBatchInput,
  PipelineConfig,
  PipelineMergeResult,
  PipelineSnapshot,
  PipelineSourceContext
} from './PipelineTypes';
import {
  DEFAULT_PIPELINE_CONFIG,
  buildVulnerabilityCacheKey,
  compareVulnerabilitiesByFreshness,
  sortVulnerabilitiesDeterministically,
  toSortedChangedVulnerabilityIds
} from './PipelineTypes';
import { normalizeVulnerabilityBatch } from './VulnerabilityBatchNormalizer';
import { AsyncTaskCoordinator } from '../../infrastructure/async/AsyncTaskCoordinator';
import { CooperativeScheduler } from '../../infrastructure/async/CooperativeScheduler';

const sleep = async (ms: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

interface CollectedFetchBatches {
  readonly batches: FetchVulnerabilityBatch[];
  readonly pagesFetched: number;
  readonly retriesPerformed: number;
  readonly totalItems: number;
  readonly warnings: readonly string[];
}

export interface IngestionPipelineRequest {
  readonly controls: SyncControls;
  readonly onEvent?: PipelineEventListener;
  readonly snapshot: PipelineSnapshot;
  readonly source: PipelineSourceContext;
  readonly sourceFeed: VulnerabilityFeed;
}

export interface IngestionPipelineResult {
  readonly cacheByKey: Map<string, Vulnerability>;
  readonly changedIds: ChangedVulnerabilityIds;
  readonly itemsDeduplicated: number;
  readonly itemsFetched: number;
  readonly itemsMerged: number;
  readonly originByKey: Map<string, string>;
  readonly pagesFetched: number;
  readonly retriesPerformed: number;
  readonly vulnerabilities: Vulnerability[];
  readonly warnings: readonly string[];
}

export interface IngestionPipelineOptions extends Partial<PipelineConfig> {
  readonly asyncTaskCoordinator?: AsyncTaskCoordinator;
  readonly cooperativeScheduler?: CooperativeScheduler;
}

export class IngestionPipeline {
  private readonly asyncTaskCoordinator: AsyncTaskCoordinator;
  private readonly config: PipelineConfig;
  private readonly cooperativeScheduler: CooperativeScheduler;

  public constructor(options: IngestionPipelineOptions = {}) {
    this.config = {
      ...DEFAULT_PIPELINE_CONFIG,
      ...options
    };
    this.asyncTaskCoordinator = options.asyncTaskCoordinator ?? new AsyncTaskCoordinator();
    this.cooperativeScheduler = options.cooperativeScheduler ?? new CooperativeScheduler();
  }

  public async run(request: IngestionPipelineRequest): Promise<IngestionPipelineResult> {
    const collected = await this.collectFetchBatches(request);
    const cacheByKey = new Map(request.snapshot.cacheByKey);
    const originByKey = new Map(request.snapshot.originByKey);
    const seenRun = new Map<string, Vulnerability>();
    const aggregateAdded = new Set<string>();
    const aggregateUpdated = new Set<string>();
    const aggregateRemoved = new Set<string>();
    let itemsMerged = 0;
    let itemsDeduplicated = 0;
    let processedItems = 0;
    let batchIndex = 0;

    for (const fetchedBatch of collected.batches) {
      for (const chunk of this.createChunkInputs(
        fetchedBatch.vulnerabilities,
        collected.totalItems,
        request.source,
        batchIndex
      )) {
        batchIndex = chunk.batchIndex + 1;
        const normalizedBatch = await this.normalizeBatch(chunk);
        processedItems += normalizedBatch.normalizedCount;

        await request.onEvent?.({
          ...this.buildEventBase(request.source, normalizedBatch.batchIndex, processedItems, collected.totalItems),
          batch: normalizedBatch,
          input: chunk,
          stage: 'transform'
        });

        const mergeResult = this.mergeNormalizedBatch(
          normalizedBatch,
          request.source,
          cacheByKey,
          originByKey,
          seenRun
        );

        itemsMerged += mergeResult.itemsMerged;
        itemsDeduplicated += mergeResult.itemsDeduplicated;
        this.mergeChangedIds(aggregateAdded, aggregateUpdated, aggregateRemoved, mergeResult.changedIds);

        await request.onEvent?.({
          ...this.buildEventBase(request.source, normalizedBatch.batchIndex, processedItems, collected.totalItems),
          mergeResult,
          stage: 'merge'
        });

        if (mergeResult.changedIds.added.length > 0 || mergeResult.changedIds.updated.length > 0) {
          await request.onEvent?.({
            ...this.buildEventBase(request.source, normalizedBatch.batchIndex, processedItems, collected.totalItems),
            changedIds: mergeResult.changedIds,
            stage: 'notify',
            vulnerabilities: sortVulnerabilitiesDeterministically(cacheByKey.values())
          });
        }

        await this.cooperativeScheduler.yieldToHost({ timeoutMs: 16 });
      }
    }

    const removedIds = this.removeMissingSnapshotItems(request.source, cacheByKey, originByKey, seenRun);
    if (removedIds.length > 0) {
      const changedIds = toSortedChangedVulnerabilityIds({ removed: removedIds });
      this.mergeChangedIds(aggregateAdded, aggregateUpdated, aggregateRemoved, changedIds);

      const mergeResult: PipelineMergeResult = {
        cacheSize: cacheByKey.size,
        changedIds,
        itemsDeduplicated: 0,
        itemsMerged: 0
      };

      await request.onEvent?.({
        ...this.buildEventBase(request.source, batchIndex, processedItems, collected.totalItems),
        mergeResult,
        stage: 'merge'
      });

      await request.onEvent?.({
        ...this.buildEventBase(request.source, batchIndex, processedItems, collected.totalItems),
        changedIds,
        stage: 'notify',
        vulnerabilities: sortVulnerabilitiesDeterministically(cacheByKey.values())
      });
    }

    return {
      cacheByKey,
      changedIds: toSortedChangedVulnerabilityIds({
        added: aggregateAdded,
        removed: aggregateRemoved,
        updated: aggregateUpdated
      }),
      itemsDeduplicated,
      itemsFetched: collected.totalItems,
      itemsMerged,
      originByKey,
      pagesFetched: collected.pagesFetched,
      retriesPerformed: collected.retriesPerformed,
      vulnerabilities: sortVulnerabilitiesDeterministically(cacheByKey.values()),
      warnings: collected.warnings
    };
  }

  private async collectFetchBatches(request: IngestionPipelineRequest): Promise<CollectedFetchBatches> {
    let delay = request.controls.backoffBaseMs;
    let retriesPerformed = 0;

    for (let attempt = 1; attempt <= request.controls.retryCount + 1; attempt += 1) {
      try {
        const batches: FetchVulnerabilityBatch[] = [];
        const warnings: string[] = [];
        let pagesFetched = 0;
        let totalItems = 0;

        for await (const batch of this.iterateFeedBatches(request.sourceFeed, request.source)) {
          batches.push(batch);
          pagesFetched += batch.pagesFetched ?? 0;
          totalItems += batch.vulnerabilities.length;
          warnings.push(...(batch.warnings ?? []));

          await request.onEvent?.({
            ...this.buildEventBase(request.source, batches.length - 1, totalItems, totalItems),
            pagesFetched,
            retriesPerformed,
            stage: 'fetch',
            warnings
          });
        }

        return {
          batches,
          pagesFetched,
          retriesPerformed,
          totalItems,
          warnings
        };
      } catch (error: unknown) {
        if (!this.isRetryable(error) || attempt > request.controls.retryCount) {
          throw error;
        }

        retriesPerformed += 1;
        const retryAfter = error instanceof RateLimitHttpError ? error.metadata.retryAfterMs : undefined;
        await sleep(retryAfter ?? delay);
        delay = Math.min(delay * 2, 30_000);
      }
    }

    return {
      batches: [],
      pagesFetched: 0,
      retriesPerformed,
      totalItems: 0,
      warnings: ['retry_budget_exhausted']
    };
  }

  private buildEventBase(
    source: PipelineSourceContext,
    batchIndex: number,
    processedItems: number,
    totalItems: number
  ): {
    batchIndex: number;
    existingCursor?: string;
    processedItems: number;
    runId: PipelineSourceContext['runId'];
    since?: string;
    sourceId: string;
    sourceName: string;
    totalItems: number;
    until: string;
  } {
    return {
      batchIndex,
      ...(source.existingCursor ? { existingCursor: source.existingCursor } : {}),
      processedItems,
      runId: source.runId,
      ...(source.since ? { since: source.since } : {}),
      sourceId: source.sourceId,
      sourceName: source.sourceName,
      totalItems,
      until: source.until
    };
  }

  private createChunkInputs(
    vulnerabilities: readonly Vulnerability[],
    totalFetchedItems: number,
    source: PipelineSourceContext,
    startingBatchIndex: number
  ): PipelineBatchInput[] {
    const batches: PipelineBatchInput[] = [];

    for (let index = 0; index < vulnerabilities.length; index += this.config.chunkSize) {
      batches.push({
        batchIndex: startingBatchIndex + batches.length,
        sourceId: source.sourceId,
        sourceName: source.sourceName,
        totalFetchedItems,
        vulnerabilities: vulnerabilities.slice(index, index + this.config.chunkSize)
      });
    }

    return batches;
  }

  private async normalizeBatch(input: PipelineBatchInput): Promise<NormalizedVulnerabilityBatch> {
    const result = await this.asyncTaskCoordinator.execute('normalize-vulnerabilities', {
      input
    }, {
      fallback: async ({ input: fallbackInput }) => ({
        batch: normalizeVulnerabilityBatch(fallbackInput)
      }),
      preferWorker: input.vulnerabilities.length >= this.config.normalizeWorkerMinimumItems
    });

    return result.batch;
  }

  private mergeNormalizedBatch(
    batch: NormalizedVulnerabilityBatch,
    source: PipelineSourceContext,
    cacheByKey: Map<string, Vulnerability>,
    originByKey: Map<string, string>,
    seenRun: Map<string, Vulnerability>
  ): PipelineMergeResult {
    const added = new Set<string>();
    const updated = new Set<string>();
    let itemsMerged = 0;
    let itemsDeduplicated = 0;

    for (const vulnerability of batch.vulnerabilities) {
      const key = buildVulnerabilityCacheKey(vulnerability);
      const previousRunItem = seenRun.get(key);

      if (previousRunItem) {
        itemsDeduplicated += 1;
        if (compareVulnerabilitiesByFreshness(vulnerability, previousRunItem) <= 0) {
          continue;
        }
      }

      seenRun.set(key, vulnerability);
      const existing = cacheByKey.get(key);
      if (!existing) {
        cacheByKey.set(key, vulnerability);
        originByKey.set(key, source.sourceId);
        added.add(key);
        itemsMerged += 1;
        continue;
      }

      if (compareVulnerabilitiesByFreshness(vulnerability, existing) > 0) {
        cacheByKey.set(key, vulnerability);
        originByKey.set(key, source.sourceId);
        updated.add(key);
        itemsMerged += 1;
      }
    }

    return {
      cacheSize: cacheByKey.size,
      changedIds: toSortedChangedVulnerabilityIds({ added, updated }),
      itemsDeduplicated,
      itemsMerged
    };
  }

  private removeMissingSnapshotItems(
    source: PipelineSourceContext,
    cacheByKey: Map<string, Vulnerability>,
    originByKey: Map<string, string>,
    seenRun: Map<string, Vulnerability>
  ): string[] {
    if (source.syncMode !== 'snapshot') {
      return [];
    }

    const removed: string[] = [];
    for (const [key, origin] of originByKey.entries()) {
      if (origin !== source.sourceId || seenRun.has(key)) {
        continue;
      }

      originByKey.delete(key);
      cacheByKey.delete(key);
      removed.push(key);
    }

    return removed.sort();
  }

  private async *iterateFeedBatches(
    sourceFeed: VulnerabilityFeed,
    source: Pick<PipelineSourceContext, 'since' | 'until'>
  ): AsyncIterable<FetchVulnerabilityBatch> {
    const options: FetchVulnerabilityOptions = {
      signal: new AbortController().signal,
      ...(source.since ? { since: source.since } : {}),
      until: source.until
    };

    if (sourceFeed.fetchVulnerabilityBatches) {
      yield* sourceFeed.fetchVulnerabilityBatches(options);
      return;
    }

    const result = await sourceFeed.fetchVulnerabilities(options);
    yield {
      pagesFetched: result.pagesFetched,
      retriesPerformed: result.retriesPerformed,
      vulnerabilities: result.vulnerabilities,
      warnings: result.warnings
    };
  }

  private isRetryable(error: unknown): boolean {
    return error instanceof RetryableNetworkError
      || error instanceof TimeoutHttpError
      || error instanceof RateLimitHttpError
      || error instanceof ServerHttpError
      || (error instanceof HttpRequestError
        && error.retryable
        && !(error instanceof ClientHttpError)
        && !(error instanceof AuthFailureHttpError));
  }

  private mergeChangedIds(
    aggregateAdded: Set<string>,
    aggregateUpdated: Set<string>,
    aggregateRemoved: Set<string>,
    changedIds: ChangedVulnerabilityIds
  ): void {
    for (const key of changedIds.added) {
      aggregateAdded.add(key);
      aggregateRemoved.delete(key);
    }
    for (const key of changedIds.updated) {
      if (!aggregateAdded.has(key)) {
        aggregateUpdated.add(key);
      }
    }
    for (const key of changedIds.removed) {
      aggregateAdded.delete(key);
      aggregateUpdated.delete(key);
      aggregateRemoved.add(key);
    }
  }
}
