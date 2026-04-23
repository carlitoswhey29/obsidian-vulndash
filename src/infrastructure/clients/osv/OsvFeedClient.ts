import type { OsvFeedConfig } from '../../../application/use-cases/types';
import type { IHttpClient, HttpResponse } from '../../../application/ports/HttpClient';
import type {
  FetchVulnerabilityOptions,
  FetchVulnerabilityResult,
  VulnerabilityFeed
} from '../../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
import { BUILT_IN_FEEDS } from '../../../domain/feeds/FeedTypes';
import { PurlNormalizer } from '../../../domain/services/PurlNormalizer';
import {
  buildVulnerabilityCacheKey,
  sortVulnerabilitiesDeterministically
} from '../../../application/pipeline/PipelineTypes';
import { ClientBase, type FeedSyncControls } from '../common/ClientBase';
import type { PersistedComponentQueryRecord } from '../../storage/VulnCacheSchema';
import type { IOsvQueryCache } from './IOsvQueryCache';
import { buildOsvVulnerabilityCacheKey } from './OsvCacheKey';
import { OsvMapper } from './OsvMapper';
import type {
  OsvBatchQueryItem,
  OsvBatchRequest,
  OsvBatchResponse,
  OsvVulnerabilityPayload
} from './OsvTypes';

const OSV_BATCH_ENDPOINT = 'https://api.osv.dev/v1/querybatch';
const MAX_OSV_BATCH_SIZE = 1000;

type CacheFreshness = 'error-state' | 'fresh-negative' | 'fresh-positive' | 'missing' | 'stale';

interface CachedQueryClassification {
  readonly freshness: CacheFreshness;
  readonly purl: string;
  readonly record?: PersistedComponentQueryRecord;
}

interface BatchChunkResult {
  readonly failedPurls: readonly string[];
  readonly continuationCount: number;
  readonly maxPagesReached: boolean;
  readonly mappedVulnerabilityCount: number;
  readonly pagesFetched: number;
  readonly resultsByPurl: ReadonlyMap<string, readonly Vulnerability[]>;
  readonly retriesPerformed: number;
}

interface PendingQuery {
  readonly pageToken: string | undefined;
  readonly purl: string;
}

interface TimedSignal {
  readonly cleanup: () => void;
  readonly signal: AbortSignal;
}

interface BatchResponseAssociation {
  readonly continuationCount: number;
  readonly failedPurls: readonly string[];
  readonly nextPending: readonly PendingQuery[];
}

interface CacheClassificationSummary {
  readonly cacheErrorStateCount: number;
  readonly cacheHitCount: number;
  readonly cacheMissCount: number;
  readonly cacheStaleCount: number;
}

export class OsvFeedClient extends ClientBase implements VulnerabilityFeed {
  public readonly id: string;
  public readonly name: string;
  public readonly syncMode = 'snapshot' as const;
  private readonly mapper: OsvMapper;

  public constructor(
    httpClient: IHttpClient,
    private readonly queryCache: IOsvQueryCache,
    private readonly getPurls: () => Promise<readonly string[]>,
    private readonly controls: FeedSyncControls,
    private readonly config: OsvFeedConfig
  ) {
    super(httpClient, config.name, controls);
    this.id = config.id;
    this.name = config.name;
    this.mapper = new OsvMapper(config.name);
  }

  public async fetchVulnerabilities(options: FetchVulnerabilityOptions): Promise<FetchVulnerabilityResult> {
    const warnings: string[] = [];
    const seenAtMs = Date.now();
    const { ignoredCount, purls, rawCount } = await this.loadNormalizedActivePurls();
    const activePurls = purls;
    const activePurlSet = new Set(activePurls);

    if (ignoredCount > 0) {
      warnings.push('ignored_invalid_purls');
    }

    await this.queryCache.markComponentQueriesSeen(activePurls, seenAtMs);
    const orphanPrunedCount = await this.queryCache.pruneOrphanedComponentQueries(activePurlSet);
    const expiredPrunedCount = await this.queryCache.pruneExpiredComponentQueries(
      seenAtMs - Math.max(this.config.cacheTtlMs, this.config.negativeCacheTtlMs)
    );

    if (activePurls.length === 0) {
      this.logFetchPlan({
        cacheErrorStateCount: 0,
        cacheHitCount: 0,
        cacheMissCount: 0,
        cacheStaleCount: 0,
        expiredPrunedCount,
        normalizedValidPurlCount: 0,
        orphanPrunedCount,
        rawActivePurlCount: rawCount
      });
      this.logFetchComplete({
        batchCount: 0,
        continuationCount: 0,
        mappedVulnerabilityCount: 0,
        partialFailureCount: 0,
        pruneExpiredCount: expiredPrunedCount,
        pruneOrphanedCount: orphanPrunedCount,
        retriesPerformed: 0,
        returnedVulnerabilityCount: 0,
        warnings
      });
      return {
        vulnerabilities: [],
        pagesFetched: 0,
        warnings,
        retriesPerformed: 0
      };
    }

    const recordsByPurl = await this.queryCache.loadComponentQueries(activePurls);
    const classifications = activePurls.map((purl) => this.evaluateFreshness(purl, recordsByPurl.get(purl), seenAtMs));
    const classificationSummary = this.summarizeClassifications(classifications);
    this.logFetchPlan({
      ...classificationSummary,
      expiredPrunedCount,
      normalizedValidPurlCount: activePurls.length,
      orphanPrunedCount,
      rawActivePurlCount: rawCount
    });
    const freshPositiveRecords = classifications
      .filter((classification): classification is CachedQueryClassification & { record: PersistedComponentQueryRecord } =>
        classification.freshness === 'fresh-positive' && Boolean(classification.record))
      .map((classification) => classification.record);

    const cachedVulnerabilities = await this.rehydrateCachedVulnerabilities(freshPositiveRecords);
    const purlsToQuery = classifications
      .filter((classification) => classification.freshness === 'missing'
        || classification.freshness === 'stale'
        || classification.freshness === 'error-state')
      .map((classification) => classification.purl);

    const queryResult = await this.fetchQueriedPurls(purlsToQuery, options.signal);
    const queriedAtMs = Date.now();
    if (queryResult.maxPagesReached) {
      warnings.push('max_pages_reached');
    }
    if (queryResult.failedPurls.length > 0) {
      warnings.push('partial_failure');
    }

    const fallbackRecords = this.selectFailedFallbackRecords(queryResult.failedPurls, recordsByPurl);
    const fallbackVulnerabilities = await this.rehydrateCachedVulnerabilities(fallbackRecords);
    const queryRecords = [
      ...this.buildSuccessfulQueryRecords(queryResult.resultsByPurl, queriedAtMs, seenAtMs),
      ...this.buildErrorQueryRecords(queryResult.failedPurls, recordsByPurl, queriedAtMs, seenAtMs)
    ];
    if (queryRecords.length > 0) {
      await this.queryCache.saveComponentQueries(queryRecords);
    }

    const queriedVulnerabilities = Array.from(queryResult.resultsByPurl.values()).flatMap((vulnerabilities) => vulnerabilities);
    const vulnerabilities = Array.from(this.dedupeVulnerabilities([
      ...cachedVulnerabilities,
      ...fallbackVulnerabilities,
      ...queriedVulnerabilities
    ]));
    this.logFetchComplete({
      batchCount: queryResult.pagesFetched,
      continuationCount: queryResult.continuationCount,
      mappedVulnerabilityCount: queryResult.mappedVulnerabilityCount,
      partialFailureCount: queryResult.failedPurls.length,
      pruneExpiredCount: expiredPrunedCount,
      pruneOrphanedCount: orphanPrunedCount,
      retriesPerformed: queryResult.retriesPerformed,
      returnedVulnerabilityCount: vulnerabilities.length,
      warnings
    });
    if (queryResult.failedPurls.length > 0) {
      console.warn('[vulndash.osv.fetch.partial_failure]', {
        source: this.name,
        feedId: this.id,
        partialFailureCount: queryResult.failedPurls.length,
        batchCount: queryResult.pagesFetched
      });
    }

    return {
      vulnerabilities,
      pagesFetched: queryResult.pagesFetched,
      warnings,
      retriesPerformed: queryResult.retriesPerformed
    };
  }

  private async loadNormalizedActivePurls(): Promise<{ ignoredCount: number; purls: readonly string[]; rawCount: number }> {
    const rawPurls = await this.getPurls();
    const normalizedPurls: string[] = [];
    const seen = new Set<string>();
    let ignoredCount = 0;

    for (const rawPurl of rawPurls) {
      const normalized = this.normalizeResolvablePurl(rawPurl);
      if (!normalized) {
        ignoredCount += 1;
        continue;
      }

      if (seen.has(normalized)) {
        continue;
      }

      seen.add(normalized);
      normalizedPurls.push(normalized);
    }

    normalizedPurls.sort((left, right) => left.localeCompare(right));

    return {
      ignoredCount,
      purls: normalizedPurls,
      rawCount: rawPurls.length
    };
  }

  private normalizeResolvablePurl(rawPurl: string): string | null {
    const normalized = PurlNormalizer.normalize(rawPurl);
    if (!normalized || !normalized.startsWith('pkg:')) {
      return null;
    }

    const pathWithoutQualifiers = normalized
      .slice(4)
      .split('#', 1)[0]
      ?.split('?', 1)[0]
      ?.replace(/^\/+/, '')
      ?.replace(/\/+$/, '') ?? '';

    if (!pathWithoutQualifiers || !pathWithoutQualifiers.includes('/')) {
      return null;
    }

    const lastAt = pathWithoutQualifiers.lastIndexOf('@');
    const lastSlash = pathWithoutQualifiers.lastIndexOf('/');
    if (lastAt <= lastSlash || lastAt === pathWithoutQualifiers.length - 1) {
      return null;
    }

    return normalized;
  }

  private evaluateFreshness(
    purl: string,
    record: PersistedComponentQueryRecord | undefined,
    nowMs: number
  ): CachedQueryClassification {
    if (!record) {
      return { freshness: 'missing', purl };
    }

    if (record.resultState === 'error') {
      return { freshness: 'error-state', purl, record };
    }

    const ageMs = Math.max(0, nowMs - record.lastQueriedAtMs);
    if (record.resultState === 'hit' && ageMs <= this.config.cacheTtlMs) {
      return { freshness: 'fresh-positive', purl, record };
    }

    if (record.resultState === 'miss' && ageMs <= this.config.negativeCacheTtlMs) {
      return { freshness: 'fresh-negative', purl, record };
    }

    return { freshness: 'stale', purl, record };
  }

  private async rehydrateCachedVulnerabilities(records: readonly PersistedComponentQueryRecord[]): Promise<readonly Vulnerability[]> {
    const keys = records.flatMap((record) => record.vulnerabilityCacheKeys);
    if (keys.length === 0) {
      return [];
    }

    const loaded = await this.queryCache.loadVulnerabilitiesByCacheKeys(keys);
    return this.dedupeVulnerabilities(loaded);
  }

  private async fetchQueriedPurls(
    purls: readonly string[],
    signal: AbortSignal
  ): Promise<{
    continuationCount: number;
    failedPurls: readonly string[];
    mappedVulnerabilityCount: number;
    maxPagesReached: boolean;
    pagesFetched: number;
    resultsByPurl: ReadonlyMap<string, readonly Vulnerability[]>;
    retriesPerformed: number;
  }> {
    if (purls.length === 0) {
      return {
        continuationCount: 0,
        failedPurls: [],
        mappedVulnerabilityCount: 0,
        maxPagesReached: false,
        pagesFetched: 0,
        resultsByPurl: new Map<string, readonly Vulnerability[]>(),
        retriesPerformed: 0
      };
    }

    const chunks = this.chunkPurls(purls, MAX_OSV_BATCH_SIZE);
    const chunkResults = await this.processWithConcurrency(chunks, this.config.maxConcurrentBatches, async (chunk) =>
      this.fetchChunk(chunk, signal)
    );

    let continuationCount = 0;
    const failedPurls: string[] = [];
    let mappedVulnerabilityCount = 0;
    let maxPagesReached = false;
    const resultsByPurl = new Map<string, readonly Vulnerability[]>();
    let pagesFetched = 0;
    let retriesPerformed = 0;

    for (const chunkResult of chunkResults) {
      continuationCount += chunkResult.continuationCount;
      pagesFetched += chunkResult.pagesFetched;
      retriesPerformed += chunkResult.retriesPerformed;
      failedPurls.push(...chunkResult.failedPurls);
      mappedVulnerabilityCount += chunkResult.mappedVulnerabilityCount;
      maxPagesReached = maxPagesReached || chunkResult.maxPagesReached;

      for (const [purl, vulnerabilities] of chunkResult.resultsByPurl) {
        resultsByPurl.set(purl, vulnerabilities);
      }
    }

    return {
      continuationCount,
      failedPurls: Array.from(new Set(failedPurls)).sort((left, right) => left.localeCompare(right)),
      mappedVulnerabilityCount,
      maxPagesReached,
      pagesFetched,
      resultsByPurl,
      retriesPerformed
    };
  }

  private chunkPurls(purls: readonly string[], chunkSize: number): readonly (readonly string[])[] {
    const chunks: string[][] = [];

    for (let index = 0; index < purls.length; index += chunkSize) {
      chunks.push(purls.slice(index, index + chunkSize));
    }

    return chunks;
  }

  private async fetchChunk(purls: readonly string[], signal: AbortSignal): Promise<BatchChunkResult> {
    const accumulated = new Map<string, OsvVulnerabilityPayload[]>();
    const failedPurls = new Set<string>();
    let continuationCount = 0;
    let pending: PendingQuery[] = purls.map((purl) => ({ pageToken: undefined, purl }));
    let maxPagesReached = false;
    let pagesFetched = 0;
    let retriesPerformed = 0;

    while (pending.length > 0 && pagesFetched < this.controls.maxPages) {
      const requestItems = pending.map((query) => this.toBatchQueryItem(query.purl, query.pageToken));

      try {
        const { response, retriesPerformed: requestRetries } = await this.executeBatchQuery(requestItems, signal);
        pagesFetched += 1;
        retriesPerformed += requestRetries;
        const association = this.associateBatchResponse(pending, response, accumulated);
        continuationCount += association.continuationCount;
        for (const purl of association.failedPurls) {
          failedPurls.add(purl);
        }
        pending = [...association.nextPending];
      } catch {
        for (const query of pending) {
          accumulated.delete(query.purl);
          failedPurls.add(query.purl);
        }

        return {
          continuationCount,
          failedPurls: Array.from(failedPurls).sort((left, right) => left.localeCompare(right)),
          mappedVulnerabilityCount: this.countMappedVulnerabilities(accumulated),
          maxPagesReached,
          pagesFetched,
          resultsByPurl: this.mapAccumulatedPayloads(accumulated),
          retriesPerformed
        };
      }
    }

    if (pending.length > 0) {
      maxPagesReached = true;
      for (const query of pending) {
        accumulated.delete(query.purl);
        failedPurls.add(query.purl);
      }
    }

    return {
      continuationCount,
      failedPurls: Array.from(failedPurls).sort((left, right) => left.localeCompare(right)),
      mappedVulnerabilityCount: this.countMappedVulnerabilities(accumulated),
      maxPagesReached,
      pagesFetched,
      resultsByPurl: this.mapAccumulatedPayloads(accumulated),
      retriesPerformed
    };
  }

  private toBatchQueryItem(purl: string, pageToken?: string): OsvBatchQueryItem {
    return {
      package: { purl },
      ...(pageToken ? { page_token: pageToken } : {})
    };
  }

  private async executeBatchQuery(
    queries: readonly OsvBatchQueryItem[],
    parentSignal: AbortSignal
  ): Promise<{ response: HttpResponse<OsvBatchResponse>; retriesPerformed: number }> {
    const timedSignal = this.createTimedSignal(parentSignal, this.config.requestTimeoutMs);

    try {
      return await this.postJsonWithResilience<OsvBatchRequest, OsvBatchResponse>({
        body: { queries },
        context: {
          provider: this.name,
          operation: 'fetchVulnerabilities',
          url: OSV_BATCH_ENDPOINT
        },
        headers: {
          Accept: 'application/json',
          'Content-Type': 'application/json',
          'User-Agent': 'obsidian-vulndash'
        },
        signal: timedSignal.signal
      });
    } finally {
      timedSignal.cleanup();
    }
  }

  private createTimedSignal(parentSignal: AbortSignal, timeoutMs: number): TimedSignal {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    const abortParent = (): void => controller.abort();

    parentSignal.addEventListener('abort', abortParent, { once: true });

    return {
      cleanup: () => {
        clearTimeout(timeoutId);
        parentSignal.removeEventListener('abort', abortParent);
      },
      signal: controller.signal
    };
  }

  private associateBatchResponse(
    pending: readonly PendingQuery[],
    response: HttpResponse<OsvBatchResponse>,
    accumulated: Map<string, OsvVulnerabilityPayload[]>
  ): BatchResponseAssociation {
    let continuationCount = 0;
    const failedPurls: string[] = [];
    const nextPending: PendingQuery[] = [];

    for (let index = 0; index < pending.length; index += 1) {
      const query = pending[index];
      if (!query) {
        continue;
      }

      const result = response.data.results?.[index];
      if (!result) {
        accumulated.delete(query.purl);
        failedPurls.push(query.purl);
        continue;
      }

      const existing = accumulated.get(query.purl) ?? [];
      if (result.vulns) {
        existing.push(...result.vulns);
      }
      accumulated.set(query.purl, existing);

      const nextPageToken = result.next_page_token?.trim();
      if (nextPageToken) {
        continuationCount += 1;
        nextPending.push({
          pageToken: nextPageToken,
          purl: query.purl
        });
      }
    }

    return {
      continuationCount,
      failedPurls,
      nextPending
    };
  }

  private mapAccumulatedPayloads(
    accumulated: ReadonlyMap<string, readonly OsvVulnerabilityPayload[]>
  ): ReadonlyMap<string, readonly Vulnerability[]> {
    const resultsByPurl = new Map<string, readonly Vulnerability[]>();

    for (const [purl, payloads] of accumulated) {
      resultsByPurl.set(purl, this.dedupeVulnerabilities(payloads.map((payload) => this.mapper.normalize(payload))));
    }

    return resultsByPurl;
  }

  private buildSuccessfulQueryRecords(
    resultsByPurl: ReadonlyMap<string, readonly Vulnerability[]>,
    queriedAtMs: number,
    seenAtMs: number
  ): readonly PersistedComponentQueryRecord[] {
    const records: PersistedComponentQueryRecord[] = [];

    for (const [purl, vulnerabilities] of resultsByPurl) {
      records.push({
        purl,
        source: BUILT_IN_FEEDS.OSV.type,
        lastQueriedAtMs: queriedAtMs,
        lastSeenInWorkspaceAtMs: seenAtMs,
        resultState: vulnerabilities.length > 0 ? 'hit' : 'miss',
        vulnerabilityCacheKeys: vulnerabilities.length > 0
          ? this.toDeterministicCacheKeys(vulnerabilities)
          : []
      });
    }

    return records;
  }

  private buildErrorQueryRecords(
    purls: readonly string[],
    existingRecordsByPurl: ReadonlyMap<string, PersistedComponentQueryRecord>,
    queriedAtMs: number,
    seenAtMs: number
  ): readonly PersistedComponentQueryRecord[] {
    return purls.map((purl) => ({
      purl,
      source: BUILT_IN_FEEDS.OSV.type,
      lastQueriedAtMs: queriedAtMs,
      lastSeenInWorkspaceAtMs: seenAtMs,
      resultState: 'error',
      vulnerabilityCacheKeys: [...(existingRecordsByPurl.get(purl)?.vulnerabilityCacheKeys ?? [])]
    }));
  }

  private selectFailedFallbackRecords(
    failedPurls: readonly string[],
    recordsByPurl: ReadonlyMap<string, PersistedComponentQueryRecord>
  ): readonly PersistedComponentQueryRecord[] {
    const fallbackRecords: PersistedComponentQueryRecord[] = [];

    for (const purl of failedPurls) {
      const record = recordsByPurl.get(purl);
      if (!record || record.vulnerabilityCacheKeys.length === 0) {
        continue;
      }

      fallbackRecords.push(record);
    }

    return fallbackRecords;
  }

  private toDeterministicCacheKeys(vulnerabilities: readonly Vulnerability[]): readonly string[] {
    return Array.from(new Set(vulnerabilities
      .map((vulnerability) => buildOsvVulnerabilityCacheKey(vulnerability.id, this.id))))
      .sort((left, right) => left.localeCompare(right));
  }

  private countMappedVulnerabilities(accumulated: ReadonlyMap<string, readonly OsvVulnerabilityPayload[]>): number {
    let mappedVulnerabilityCount = 0;

    for (const payloads of accumulated.values()) {
      mappedVulnerabilityCount += payloads.length;
    }

    return mappedVulnerabilityCount;
  }

  private dedupeVulnerabilities(vulnerabilities: Iterable<Vulnerability>): readonly Vulnerability[] {
    const deduped = new Map<string, Vulnerability>();

    for (const vulnerability of vulnerabilities) {
      deduped.set(buildVulnerabilityCacheKey(vulnerability), vulnerability);
    }

    return sortVulnerabilitiesDeterministically(deduped.values());
  }

  private summarizeClassifications(classifications: readonly CachedQueryClassification[]): CacheClassificationSummary {
    let cacheErrorStateCount = 0;
    let cacheHitCount = 0;
    let cacheMissCount = 0;
    let cacheStaleCount = 0;

    for (const classification of classifications) {
      switch (classification.freshness) {
        case 'fresh-positive':
          cacheHitCount += 1;
          break;
        case 'fresh-negative':
        case 'missing':
          cacheMissCount += 1;
          break;
        case 'stale':
          cacheStaleCount += 1;
          break;
        case 'error-state':
          cacheErrorStateCount += 1;
          break;
        default:
          break;
      }
    }

    return {
      cacheErrorStateCount,
      cacheHitCount,
      cacheMissCount,
      cacheStaleCount
    };
  }

  private logFetchPlan(context: {
    readonly cacheErrorStateCount: number;
    readonly cacheHitCount: number;
    readonly cacheMissCount: number;
    readonly cacheStaleCount: number;
    readonly expiredPrunedCount: number;
    readonly normalizedValidPurlCount: number;
    readonly orphanPrunedCount: number;
    readonly rawActivePurlCount: number;
  }): void {
    console.info('[vulndash.osv.fetch.plan]', {
      source: this.name,
      feedId: this.id,
      rawActivePurlCount: context.rawActivePurlCount,
      normalizedValidPurlCount: context.normalizedValidPurlCount,
      cacheHitCount: context.cacheHitCount,
      cacheMissCount: context.cacheMissCount,
      cacheStaleCount: context.cacheStaleCount,
      cacheErrorStateCount: context.cacheErrorStateCount,
      pruneOrphanedCount: context.orphanPrunedCount,
      pruneExpiredCount: context.expiredPrunedCount
    });
  }

  private logFetchComplete(context: {
    readonly batchCount: number;
    readonly continuationCount: number;
    readonly mappedVulnerabilityCount: number;
    readonly partialFailureCount: number;
    readonly pruneExpiredCount: number;
    readonly pruneOrphanedCount: number;
    readonly retriesPerformed: number;
    readonly returnedVulnerabilityCount: number;
    readonly warnings: readonly string[];
  }): void {
    console.info('[vulndash.osv.fetch.complete]', {
      source: this.name,
      feedId: this.id,
      osvBatchCount: context.batchCount,
      continuationCount: context.continuationCount,
      mappedVulnerabilityCount: context.mappedVulnerabilityCount,
      returnedVulnerabilityCount: context.returnedVulnerabilityCount,
      partialFailureCount: context.partialFailureCount,
      pruneOrphanedCount: context.pruneOrphanedCount,
      pruneExpiredCount: context.pruneExpiredCount,
      retriesPerformed: context.retriesPerformed,
      warnings: [...context.warnings]
    });
  }

  private async processWithConcurrency<TInput, TOutput>(
    items: readonly TInput[],
    concurrency: number,
    worker: (item: TInput, index: number) => Promise<TOutput>
  ): Promise<readonly TOutput[]> {
    if (items.length === 0) {
      return [];
    }

    const results = new Array<TOutput>(items.length);
    let nextIndex = 0;
    const workerCount = Math.max(1, Math.min(concurrency, items.length));

    await Promise.all(Array.from({ length: workerCount }, async () => {
      while (nextIndex < items.length) {
        const currentIndex = nextIndex;
        nextIndex += 1;
        results[currentIndex] = await worker(items[currentIndex] as TInput, currentIndex);
      }
    }));

    return results;
  }
}
