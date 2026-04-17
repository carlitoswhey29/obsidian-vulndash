import type { FeedConfig } from '../../application/use-cases/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { SyncMetadataRepository } from './SyncMetadataRepository';
import { VulnCacheRepository } from './VulnCacheRepository';

export interface LegacyPersistedPluginData {
  readonly cache?: unknown;
  readonly cachedVulnerabilities?: unknown;
  readonly sourceSyncCursor?: Record<string, string>;
  readonly vulnerabilities?: unknown;
}

export interface LegacyMigrationResult {
  readonly migratedCursorCount: number;
  readonly migratedVulnerabilityCount: number;
  readonly removedLegacyFields: boolean;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === 'string');

const isVulnerability = (value: unknown): value is Vulnerability => {
  if (!isRecord(value)) {
    return false;
  }

  return typeof value.id === 'string'
    && typeof value.source === 'string'
    && typeof value.title === 'string'
    && typeof value.summary === 'string'
    && typeof value.publishedAt === 'string'
    && typeof value.updatedAt === 'string'
    && typeof value.cvssScore === 'number'
    && typeof value.severity === 'string'
    && isStringArray(value.references)
    && isStringArray(value.affectedProducts);
};

const collectLegacyVulnerabilities = (data: LegacyPersistedPluginData | null): Vulnerability[] => {
  if (!data) {
    return [];
  }

  const candidates = [data.cachedVulnerabilities, data.vulnerabilities, data.cache];
  for (const candidate of candidates) {
    if (!Array.isArray(candidate)) {
      continue;
    }

    const vulnerabilities = candidate.filter(isVulnerability);
    if (vulnerabilities.length > 0) {
      return vulnerabilities;
    }
  }

  return [];
};

const resolveLegacySourceId = (source: string, feeds: readonly FeedConfig[]): string => {
  const trimmed = source.trim();
  const feedByExactName = feeds.find((feed) => feed.name === trimmed);
  if (feedByExactName) {
    return feedByExactName.id;
  }

  const normalized = trimmed.toLowerCase();
  const feedByNormalizedName = feeds.find((feed) => feed.name.trim().toLowerCase() === normalized);
  if (feedByNormalizedName) {
    return feedByNormalizedName.id;
  }

  if (normalized === 'github') {
    return 'github-advisories-default';
  }
  if (normalized === 'nvd') {
    return 'nvd-default';
  }

  return normalized.replace(/[^a-z0-9._-]+/g, '-');
};

export class LegacyDataMigration {
  public constructor(
    private readonly cacheRepository: VulnCacheRepository,
    private readonly syncMetadataRepository: SyncMetadataRepository
  ) {}

  public async migrate(data: LegacyPersistedPluginData | null, feeds: readonly FeedConfig[]): Promise<LegacyMigrationResult> {
    if (!data) {
      return {
        migratedCursorCount: 0,
        migratedVulnerabilityCount: 0,
        removedLegacyFields: false
      };
    }

    const legacyVulnerabilities = collectLegacyVulnerabilities(data);
    const groupedBySource = new Map<string, Vulnerability[]>();
    for (const vulnerability of legacyVulnerabilities) {
      const sourceId = resolveLegacySourceId(vulnerability.source, feeds);
      const current = groupedBySource.get(sourceId) ?? [];
      current.push(vulnerability);
      groupedBySource.set(sourceId, current);
    }

    for (const [sourceId, vulnerabilities] of groupedBySource.entries()) {
      const lastSeenAt = data.sourceSyncCursor?.[sourceId]
        ?? data.sourceSyncCursor?.[vulnerabilities[0]?.source ?? '']
        ?? new Date().toISOString();
      await this.cacheRepository.importLegacySnapshot(sourceId, vulnerabilities, lastSeenAt);
    }

    let migratedCursorCount = 0;
    for (const [sourceId, successfulAt] of Object.entries(data.sourceSyncCursor ?? {})) {
      if (!successfulAt.trim()) {
        continue;
      }

      const resolvedSourceId = resolveLegacySourceId(sourceId, feeds);
      await this.syncMetadataRepository.recordSuccess(resolvedSourceId, successfulAt, successfulAt);
      migratedCursorCount += 1;
    }

    const removedLegacyFields = Array.isArray(data.cache)
      || Array.isArray(data.cachedVulnerabilities)
      || Array.isArray(data.vulnerabilities)
      || Object.keys(data.sourceSyncCursor ?? {}).length > 0;

    return {
      migratedCursorCount,
      migratedVulnerabilityCount: legacyVulnerabilities.length,
      removedLegacyFields
    };
  }
}
