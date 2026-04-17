import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';
import type { SyncControls } from './types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { PipelineEvent, PipelineEventListener } from '../pipeline/PipelineEvents';
import { IngestionPipeline, type IngestionPipelineResult } from '../pipeline/IngestionPipeline';
import { PipelineRunRegistry } from '../pipeline/PipelineRunRegistry';
import type { PipelineConfig, PipelineSnapshot } from '../pipeline/PipelineTypes';
import {
  DEFAULT_PIPELINE_CONFIG,
  sortVulnerabilitiesDeterministically
} from '../pipeline/PipelineTypes';

export interface SyncResult {
  source: string;
  startedAt: string;
  completedAt: string;
  success: boolean;
  itemsFetched: number;
  itemsMerged: number;
  itemsDeduplicated: number;
  pagesFetched: number;
  retriesPerformed: number;
  warnings: string[];
  errorSummary?: string;
}

export interface SyncState {
  cache: Vulnerability[];
  sourceSyncCursor: Record<string, string>;
}

export interface SyncOutcome {
  vulnerabilities: Vulnerability[];
  results: SyncResult[];
  sourceSyncCursor: Record<string, string>;
}

export interface VulnerabilityCacheStore {
  importLegacySnapshot?(sourceId: string, vulnerabilities: readonly Vulnerability[], lastSeenAt: string): Promise<void>;
  loadLatest(limit: number, pageSize: number): Promise<Vulnerability[]>;
  loadSourceSnapshot(sourceId: string): Promise<PipelineSnapshot>;
  replaceSourceSnapshot(sourceId: string, vulnerabilities: readonly Vulnerability[], syncedAt: string): Promise<void>;
}

export interface SyncMetadataStore {
  getLastSuccessfulSyncAt(sourceId: string): Promise<string | null>;
  recordAttempt(sourceId: string, attemptedAt: string): Promise<void>;
  recordSuccess(sourceId: string, attemptedAt: string, successfulAt: string): Promise<void>;
}

export interface VulnerabilitySyncPersistenceOptions {
  readonly cacheHydrationLimit: number;
  readonly cacheHydrationPageSize: number;
  readonly cacheStore: VulnerabilityCacheStore;
  readonly metadataStore: SyncMetadataStore;
}

export interface VulnerabilitySyncServiceOptions {
  readonly controls: SyncControls;
  readonly feeds: VulnerabilityFeed[];
  readonly onPipelineEvent?: PipelineEventListener;
  readonly persistence?: VulnerabilitySyncPersistenceOptions;
  readonly pipelineConfig?: Partial<PipelineConfig>;
  readonly state: SyncState;
}

export class VulnerabilitySyncService {
  private activeDrainPromise: Promise<SyncOutcome> | null = null;
  private cacheByKey = new Map<string, Vulnerability>();
  private controls: SyncControls;
  private feeds: VulnerabilityFeed[];
  private readonly onPipelineEvent: PipelineEventListener | undefined;
  private originByKey = new Map<string, string>();
  private pendingSyncRequested = false;
  private readonly persistence: VulnerabilitySyncPersistenceOptions | null;
  private readonly pipeline: IngestionPipeline;
  private readonly runRegistry = new PipelineRunRegistry();
  private sourceSyncCursor: Record<string, string>;

  public constructor(options: VulnerabilitySyncServiceOptions) {
    this.controls = { ...options.controls };
    this.feeds = [...options.feeds];
    this.onPipelineEvent = options.onPipelineEvent;
    this.persistence = options.persistence ?? null;
    this.pipeline = new IngestionPipeline({
      ...DEFAULT_PIPELINE_CONFIG,
      ...(options.pipelineConfig ?? {})
    });
    this.sourceSyncCursor = { ...options.state.sourceSyncCursor };

    for (const vulnerability of options.state.cache) {
      this.cacheByKey.set(`${vulnerability.source}:${vulnerability.id}`, vulnerability);
    }
  }

  public updateConfiguration(feeds: VulnerabilityFeed[], controls: SyncControls): void {
    this.feeds = [...feeds];
    this.controls = { ...controls };
  }

  public async syncNow(): Promise<SyncOutcome> {
    if (this.activeDrainPromise) {
      this.pendingSyncRequested = true;
      return this.activeDrainPromise;
    }

    this.activeDrainPromise = this.executeDrain();
    try {
      return await this.activeDrainPromise;
    } finally {
      this.activeDrainPromise = null;
    }
  }

  private async executeDrain(): Promise<SyncOutcome> {
    let latestOutcome = await this.executeOnce();
    while (this.pendingSyncRequested) {
      this.pendingSyncRequested = false;
      latestOutcome = await this.executeOnce();
    }

    return latestOutcome;
  }

  private async executeOnce(): Promise<SyncOutcome> {
    const results: SyncResult[] = [];

    for (const feed of this.feeds) {
      const result = await this.syncFeed(feed);
      results.push(result);
    }

    return {
      results,
      sourceSyncCursor: { ...this.sourceSyncCursor },
      vulnerabilities: await this.loadOutcomeVulnerabilities()
    };
  }

  private async loadOutcomeVulnerabilities(): Promise<Vulnerability[]> {
    if (!this.persistence) {
      return sortVulnerabilitiesDeterministically(this.cacheByKey.values());
    }

    return this.persistence.cacheStore.loadLatest(
      this.persistence.cacheHydrationLimit,
      this.persistence.cacheHydrationPageSize
    );
  }

  private async syncFeed(feed: VulnerabilityFeed): Promise<SyncResult> {
    const startedAt = new Date().toISOString();
    const warnings: string[] = [];
    const until = startedAt;
    const existingCursor = await this.getExistingCursor(feed.id);
    const since = existingCursor
      ? new Date(Date.parse(existingCursor) - this.controls.overlapWindowMs).toISOString()
      : new Date(Date.parse(until) - this.controls.bootstrapLookbackMs).toISOString();

    console.info('[vulndash.sync.start]', {
      bootstrapLookbackMs: this.controls.bootstrapLookbackMs,
      cursor: existingCursor,
      feedId: feed.id,
      overlapWindowMs: this.controls.overlapWindowMs,
      since,
      source: feed.name,
      until
    });

    const run = this.runRegistry.start(feed.id);

    try {
      if (this.persistence) {
        await this.persistence.metadataStore.recordAttempt(feed.id, startedAt);
      }

      const snapshot = this.persistence
        ? await this.persistence.cacheStore.loadSourceSnapshot(feed.id)
        : {
          cacheByKey: this.cacheByKey,
          originByKey: this.originByKey
        };

      const pipelineResult = await this.pipeline.run({
        controls: this.controls,
        ...(this.onPipelineEvent ? {
          onEvent: async (event) => this.handlePipelineEventProxy(event)
        } : {}),
        snapshot,
        source: {
          ...(existingCursor ? { existingCursor } : {}),
          runId: run.runId,
          since,
          sourceId: feed.id,
          sourceName: feed.name,
          syncMode: feed.syncMode ?? 'incremental',
          until
        },
        sourceFeed: feed
      });

      if (!this.runRegistry.isCurrent(run)) {
        return {
          completedAt: new Date().toISOString(),
          itemsDeduplicated: 0,
          itemsFetched: 0,
          itemsMerged: 0,
          pagesFetched: 0,
          retriesPerformed: 0,
          source: feed.name,
          startedAt,
          success: false,
          warnings: ['stale_pipeline_run']
        };
      }

      await this.commitPipelineResult(feed.id, until, pipelineResult);
      warnings.push(...pipelineResult.warnings);

      console.info('[vulndash.sync.merge]', {
        deduplicated: pipelineResult.itemsDeduplicated,
        feedId: feed.id,
        fetched: pipelineResult.itemsFetched,
        merged: pipelineResult.itemsMerged,
        pagesFetched: pipelineResult.pagesFetched,
        source: feed.name,
        warnings: pipelineResult.warnings
      });

      console.info('[vulndash.sync.cursor.advance]', {
        feedId: feed.id,
        nextCursor: until,
        previousCursor: existingCursor,
        reason: 'full_sync_success',
        source: feed.name
      });

      const successResult: SyncResult = {
        completedAt: new Date().toISOString(),
        itemsDeduplicated: pipelineResult.itemsDeduplicated,
        itemsFetched: pipelineResult.itemsFetched,
        itemsMerged: pipelineResult.itemsMerged,
        pagesFetched: pipelineResult.pagesFetched,
        retriesPerformed: pipelineResult.retriesPerformed,
        source: feed.name,
        startedAt,
        success: true,
        warnings
      };

      console.info('[vulndash.sync.success]', successResult);
      return successResult;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown sync error';
      const failureResult: SyncResult = {
        completedAt: new Date().toISOString(),
        itemsDeduplicated: 0,
        itemsFetched: 0,
        itemsMerged: 0,
        pagesFetched: 0,
        retriesPerformed: 0,
        source: feed.name,
        startedAt,
        success: false,
        warnings,
        errorSummary: message
      };

      console.info('[vulndash.sync.cursor.skip]', {
        cursorRetained: existingCursor,
        feedId: feed.id,
        reason: 'sync_failed',
        source: feed.name
      });
      console.warn('[vulndash.sync.failure]', failureResult);
      return failureResult;
    } finally {
      this.runRegistry.finish(run);
    }
  }

  private async commitPipelineResult(feedId: string, until: string, pipelineResult: IngestionPipelineResult): Promise<void> {
    if (this.persistence) {
      await this.persistence.cacheStore.replaceSourceSnapshot(feedId, pipelineResult.vulnerabilities, until);
      await this.persistence.metadataStore.recordSuccess(feedId, until, until);
    } else {
      this.cacheByKey = pipelineResult.cacheByKey;
      this.originByKey = pipelineResult.originByKey;
    }

    this.sourceSyncCursor[feedId] = until;
  }

  private async getExistingCursor(feedId: string): Promise<string | undefined> {
    if (!this.persistence) {
      return this.sourceSyncCursor[feedId];
    }

    const existingCursor = await this.persistence.metadataStore.getLastSuccessfulSyncAt(feedId)
      ?? this.sourceSyncCursor[feedId];
    if (existingCursor) {
      this.sourceSyncCursor[feedId] = existingCursor;
    }
    return existingCursor;
  }

  private async handlePipelineEventProxy(event: PipelineEvent): Promise<void> {
    if (!this.onPipelineEvent) {
      return;
    }

    if (this.persistence && event.stage === 'notify') {
      return;
    }

    await this.onPipelineEvent(event);
  }
}
