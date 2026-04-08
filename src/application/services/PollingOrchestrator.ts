import {
  ClientHttpError,
  HttpRequestError,
  RateLimitHttpError,
  RetryableNetworkError,
  ServerHttpError,
  TimeoutHttpError
} from '../ports/HttpRequestError';
import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { SyncControls } from './types';

const sleep = async (ms: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

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

interface PollingState {
  cache: Vulnerability[];
  sourceSyncCursor: Record<string, string>;
}

export interface PollingOutcome {
  vulnerabilities: Vulnerability[];
  results: SyncResult[];
  sourceSyncCursor: Record<string, string>;
}

export class PollingOrchestrator {
  private running = false;
  private cacheByKey = new Map<string, Vulnerability>();
  private sourceSyncCursor: Record<string, string>;

  public constructor(
    private readonly feeds: VulnerabilityFeed[],
    private readonly controls: SyncControls,
    state: PollingState
  ) {
    for (const item of state.cache) {
      this.cacheByKey.set(this.cacheKey(item), item);
    }
    this.sourceSyncCursor = { ...state.sourceSyncCursor };
  }

  public async pollOnce(): Promise<PollingOutcome> {
    const results: SyncResult[] = [];

    for (const feed of this.feeds) {
      const result = await this.syncFeed(feed);
      results.push(result);
    }

    const vulnerabilities = Array.from(this.cacheByKey.values()).sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));
    return { vulnerabilities, results, sourceSyncCursor: { ...this.sourceSyncCursor } };
  }

  public start(intervalMs: number, callback: (outcome: PollingOutcome) => void): () => void {
    this.running = true;

    const execute = async (): Promise<void> => {
      if (!this.running) return;
      const outcome = await this.pollOnce();
      callback(outcome);
      if (this.running) {
        window.setTimeout(() => {
          void execute();
        }, intervalMs);
      }
    };

    void execute();

    return () => {
      this.running = false;
    };
  }

  private async syncFeed(feed: VulnerabilityFeed): Promise<SyncResult> {
    const startedAt = new Date().toISOString();
    const warnings: string[] = [];
    const until = startedAt;
    const existingCursor = this.sourceSyncCursor[feed.id];
    const since = existingCursor
      ? new Date(Date.parse(existingCursor) - this.controls.overlapWindowMs).toISOString()
      : new Date(Date.parse(until) - this.controls.bootstrapLookbackMs).toISOString();

    console.info('[vulndash.sync.start]', {
      source: feed.name,
      feedId: feed.id,
      cursor: existingCursor,
      since,
      until,
      overlapWindowMs: this.controls.overlapWindowMs,
      bootstrapLookbackMs: this.controls.bootstrapLookbackMs
    });

    let retriesPerformed = 0;
    let pagesFetched = 0;
    let itemsFetched = 0;
    let itemsMerged = 0;
    let itemsDeduplicated = 0;

    try {
      const fetchResult = await this.fetchWithBackoff(feed, since, until);
      retriesPerformed = fetchResult.retriesPerformed;
      pagesFetched = fetchResult.pagesFetched;
      itemsFetched = fetchResult.vulnerabilities.length;
      warnings.push(...fetchResult.warnings);

      const merged = this.mergeIntoCache(fetchResult.vulnerabilities);
      itemsMerged = merged.itemsMerged;
      itemsDeduplicated = merged.itemsDeduplicated;

      console.info('[vulndash.sync.merge]', {
        source: feed.name,
        feedId: feed.id,
        fetched: fetchResult.vulnerabilities.length,
        merged: merged.itemsMerged,
        deduplicated: merged.itemsDeduplicated,
        pagesFetched: fetchResult.pagesFetched,
        warnings: fetchResult.warnings
      });

      this.sourceSyncCursor[feed.id] = until;

      const successResult: SyncResult = {
        source: feed.name,
        startedAt,
        completedAt: new Date().toISOString(),
        success: true,
        itemsFetched,
        itemsMerged,
        itemsDeduplicated,
        pagesFetched,
        retriesPerformed,
        warnings
      };
      console.info('[vulndash.sync.success]', successResult);
      return successResult;
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'Unknown sync error';
      const failureResult: SyncResult = {
        source: feed.name,
        startedAt,
        completedAt: new Date().toISOString(),
        success: false,
        itemsFetched,
        itemsMerged,
        itemsDeduplicated,
        pagesFetched,
        retriesPerformed,
        warnings,
        errorSummary: message
      };
      console.warn('[vulndash.sync.failure]', failureResult);
      return failureResult;
    }
  }

  private async fetchWithBackoff(feed: VulnerabilityFeed, since: string | undefined, until: string): Promise<{
    vulnerabilities: Vulnerability[];
    pagesFetched: number;
    warnings: string[];
    retriesPerformed: number;
  }> {
    let delay = this.controls.backoffBaseMs;
    let retriesPerformed = 0;

    for (let attempt = 1; attempt <= this.controls.retryCount + 1; attempt += 1) {
      try {
        const response = await feed.fetchVulnerabilities({
          signal: new AbortController().signal,
          ...(since ? { since } : {}),
          until
        });
        return {
          vulnerabilities: response.vulnerabilities,
          pagesFetched: response.pagesFetched,
          warnings: response.warnings,
          retriesPerformed
        };
      } catch (error: unknown) {
        if (!this.isRetryable(error)) {
          throw error;
        }

        if (attempt > this.controls.retryCount) {
          throw error;
        }

        retriesPerformed += 1;
        const retryAfter = error instanceof RateLimitHttpError ? error.metadata.retryAfterMs : undefined;
        await sleep(retryAfter ?? delay);
        delay = Math.min(delay * 2, 30_000);
      }
    }

    return { vulnerabilities: [], pagesFetched: 0, warnings: ['retry_budget_exhausted'], retriesPerformed };
  }

  private isRetryable(error: unknown): boolean {
    return error instanceof RetryableNetworkError
      || error instanceof TimeoutHttpError
      || error instanceof RateLimitHttpError
      || error instanceof ServerHttpError
      || (error instanceof HttpRequestError && error.retryable)
      || (!(error instanceof ClientHttpError) && error instanceof Error);
  }

  private mergeIntoCache(items: Vulnerability[]): { itemsMerged: number; itemsDeduplicated: number } {
    let itemsMerged = 0;
    let itemsDeduplicated = 0;
    const seenRun = new Set<string>();

    for (const item of items) {
      const key = this.cacheKey(item);
      if (seenRun.has(key)) {
        itemsDeduplicated += 1;
        continue;
      }
      seenRun.add(key);

      const existing = this.cacheByKey.get(key);
      if (!existing || Date.parse(item.updatedAt) > Date.parse(existing.updatedAt)) {
        this.cacheByKey.set(key, item);
        itemsMerged += 1;
      }
    }

    return { itemsMerged, itemsDeduplicated };
  }

  private cacheKey(item: Vulnerability): string {
    return `${item.source}:${item.id}`;
  }
}
