import type { OsvFeedConfig } from '../../../application/use-cases/types';
import type { IHttpClient, HttpResponse } from '../../../application/ports/HttpClient';
import type {
  FetchVulnerabilityOptions,
  FetchVulnerabilityResult,
  VulnerabilityFeed
} from '../../../application/ports/VulnerabilityFeed';
import type { Vulnerability } from '../../../domain/entities/Vulnerability';
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

export class OsvFeedClient extends ClientBase implements VulnerabilityFeed {
  public readonly id: string;
  public readonly name: string;
  public readonly syncMode = 'snapshot' as const;
  private readonly mapper: OsvMapper;

  public constructor(
    httpClient: IHttpClient,
    private readonly queryCache: IOsvQueryCache,
    private readonly getPurls: () => Promise<readonly string[]>,
    controls: FeedSyncControls,
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
    const { ignoredCount, purls } = await this.loadNormalizedActivePurls();
    const activePurls = purls;
    const activePurlSet = new Set(activePurls);

    if (ignoredCount > 0) {
      warnings.push('ignored_invalid_purls');
    }

    await this.queryCache.pruneOrphanedComponentQueries(activePurlSet);
    await this.queryCache.pruneExpiredComponentQueries(
      seenAtMs - Math.max(this.config.cacheTtlMs, this.config.negativeCacheTtlMs)
    );
    await this.queryCache.markComponentQueriesSeen(activePurls, seenAtMs);

    if (activePurls.length === 0) {
      return {
        vulnerabilities: [],
        pagesFetched: 0,
        warnings,
        retriesPerformed: 0
      };
    }

    const recordsByPurl = await this.queryCache.loadComponentQueries(activePurls);
    const classifications = activePurls.map((purl) => this.evaluateFreshness(purl, recordsByPurl.get(purl), seenAtMs));
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

    if (queryResult.failedPurls.length > 0) {
      await this.queryCache.saveComponentQueries(this.buildErrorQueryRecords(queryResult.failedPurls, queriedAtMs, seenAtMs));
      throw new Error(`OSV snapshot query failed for ${queryResult.failedPurls.length} active PURLs.`);
    }

    const queryRecords = this.buildSuccessfulQueryRecords(queryResult.resultsByPurl, queriedAtMs, seenAtMs);
    if (queryRecords.length > 0) {
      await this.queryCache.saveComponentQueries(queryRecords);
    }

    const queriedVulnerabilities = Array.from(queryResult.resultsByPurl.values()).flatMap((vulnerabilities) => vulnerabilities);
    const vulnerabilities = Array.from(this.dedupeVulnerabilities([...cachedVulnerabilities, ...queriedVulnerabilities]));

    return {
      vulnerabilities,
      pagesFetched: queryResult.pagesFetched,
      warnings,
      retriesPerformed: queryResult.retriesPerformed
    };
  }

  private async loadNormalizedActivePurls(): Promise<{ ignoredCount: number; purls: readonly string[] }> {
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
      purls: normalizedPurls
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
    failedPurls: readonly string[];
    pagesFetched: number;
    resultsByPurl: ReadonlyMap<string, readonly Vulnerability[]>;
    retriesPerformed: number;
  }> {
    const chunks = this.chunkPurls(purls, MAX_OSV_BATCH_SIZE);
    const chunkResults = await this.processWithConcurrency(chunks, this.config.maxConcurrentBatches, async (chunk) =>
      this.fetchChunk(chunk, signal)
    );

    const failedPurls: string[] = [];
    const resultsByPurl = new Map<string, readonly Vulnerability[]>();
    let pagesFetched = 0;
    let retriesPerformed = 0;

    for (const chunkResult of chunkResults) {
      pagesFetched += chunkResult.pagesFetched;
      retriesPerformed += chunkResult.retriesPerformed;
      failedPurls.push(...chunkResult.failedPurls);

      for (const [purl, vulnerabilities] of chunkResult.resultsByPurl) {
        resultsByPurl.set(purl, vulnerabilities);
      }
    }

    return {
      failedPurls,
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
    let pending: PendingQuery[] = purls.map((purl) => ({ pageToken: undefined, purl }));
    let pagesFetched = 0;
    let retriesPerformed = 0;

    while (pending.length > 0) {
      const requestItems = pending.map((query) => this.toBatchQueryItem(query.purl, query.pageToken));

      try {
        const { response, retriesPerformed: requestRetries } = await this.executeBatchQuery(requestItems, signal);
        pagesFetched += 1;
        retriesPerformed += requestRetries;
        pending = this.associateBatchResponse(pending, response, accumulated);
      } catch {
        for (const query of pending) {
          accumulated.delete(query.purl);
        }

        return {
          failedPurls: pending.map((query) => query.purl),
          pagesFetched,
          resultsByPurl: this.mapAccumulatedPayloads(accumulated),
          retriesPerformed
        };
      }
    }

    return {
      failedPurls: [],
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
  ): PendingQuery[] {
    const nextPending: PendingQuery[] = [];

    for (let index = 0; index < pending.length; index += 1) {
      const query = pending[index];
      if (!query) {
        continue;
      }

      const result = response.data.results?.[index];
      const existing = accumulated.get(query.purl) ?? [];
      if (result?.vulns) {
        existing.push(...result.vulns);
      }
      accumulated.set(query.purl, existing);

      const nextPageToken = result?.next_page_token?.trim();
      if (nextPageToken) {
        nextPending.push({
          pageToken: nextPageToken,
          purl: query.purl
        });
      }
    }

    return nextPending;
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
        source: 'osv',
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
    queriedAtMs: number,
    seenAtMs: number
  ): readonly PersistedComponentQueryRecord[] {
    return purls.map((purl) => ({
      purl,
      source: 'osv',
      lastQueriedAtMs: queriedAtMs,
      lastSeenInWorkspaceAtMs: seenAtMs,
      resultState: 'error',
      vulnerabilityCacheKeys: []
    }));
  }

  private toDeterministicCacheKeys(vulnerabilities: readonly Vulnerability[]): readonly string[] {
    return Array.from(new Set(vulnerabilities
      .map((vulnerability) => buildOsvVulnerabilityCacheKey(vulnerability.id, this.id))))
      .sort((left, right) => left.localeCompare(right));
  }

  private dedupeVulnerabilities(vulnerabilities: Iterable<Vulnerability>): readonly Vulnerability[] {
    const deduped = new Map<string, Vulnerability>();

    for (const vulnerability of vulnerabilities) {
      deduped.set(buildVulnerabilityCacheKey(vulnerability), vulnerability);
    }

    return sortVulnerabilitiesDeterministically(deduped.values());
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
