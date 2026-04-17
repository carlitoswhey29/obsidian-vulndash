import type { Vulnerability } from '../../domain/entities/Vulnerability';

export const VULN_CACHE_DB_NAME = 'vulndash-cache';
export const VULN_CACHE_DB_VERSION = 1;

export const VULN_CACHE_STORES = {
  databaseMetadata: 'database-metadata',
  syncMetadata: 'sync-metadata',
  vulnerabilities: 'vulnerabilities'
} as const;

export const VULN_CACHE_INDEXES = {
  byLastSeenAt: 'by-last-seen-at',
  byRetentionRank: 'by-retention-rank',
  bySourceId: 'by-source-id'
} as const;

export interface PersistedVulnerabilityRecord {
  readonly cacheKey: string;
  readonly createdAtMs: number;
  readonly freshnessPublishedAtMs: number;
  readonly freshnessUpdatedAtMs: number;
  readonly lastSeenAt: string;
  readonly lastSeenAtMs: number;
  readonly retentionRank: readonly [number, number, string];
  readonly sourceId: string;
  readonly vulnerability: Vulnerability;
  readonly vulnerabilityId: string;
}

export interface PersistedSyncMetadataRecord {
  readonly cacheSchemaVersion: number;
  readonly lastAttemptedSyncAt: string;
  readonly lastSuccessfulSyncAt?: string;
  readonly sourceId: string;
  readonly updatedAtMs: number;
}

export interface PersistedDatabaseMetadataRecord {
  readonly key: string;
  readonly updatedAtMs: number;
  readonly value: string;
}

export interface CacheRetentionSettings {
  readonly hardCap: number;
  readonly hydrateMaxItems: number;
  readonly hydratePageSize: number;
  readonly pruneBatchSize: number;
  readonly ttlMs: number;
}

interface IndexEnsurer {
  readonly createIndex: (name: string, keyPath: string | string[], options?: IDBIndexParameters) => void;
  readonly indexNames: DOMStringList;
}

interface StoreEnsurer extends IndexEnsurer {
  readonly keyPath: string | string[] | null;
}

interface ObjectStoreNamesReader {
  readonly contains: (name: string) => boolean;
}

interface SchemaDatabase {
  readonly objectStoreNames: ObjectStoreNamesReader;
  createObjectStore(name: string, options?: IDBObjectStoreParameters): StoreEnsurer;
  transaction(storeNames: string | string[], mode?: IDBTransactionMode): {
    objectStore(name: string): StoreEnsurer;
  };
}

const ensureIndex = (
  store: IndexEnsurer,
  name: string,
  keyPath: string | string[],
  options?: IDBIndexParameters
): void => {
  if (!store.indexNames.contains(name)) {
    store.createIndex(name, keyPath, options);
  }
};

const ensureStore = (
  database: SchemaDatabase,
  name: string,
  options?: IDBObjectStoreParameters
): StoreEnsurer => {
  if (!database.objectStoreNames.contains(name)) {
    return database.createObjectStore(name, options);
  }

  return database.transaction(name, 'versionchange').objectStore(name);
};

export const buildPersistedVulnerabilityKey = (sourceId: string, vulnerabilityId: string): string =>
  `${sourceId.trim()}::${vulnerabilityId.trim()}`;

export const getVulnerabilityFreshnessPublishedAtMs = (vulnerability: Pick<Vulnerability, 'publishedAt'>): number => {
  const parsed = Date.parse(vulnerability.publishedAt);
  return Number.isFinite(parsed) ? parsed : 0;
};

export const getVulnerabilityFreshnessUpdatedAtMs = (vulnerability: Pick<Vulnerability, 'publishedAt' | 'updatedAt'>): number => {
  const updatedAtMs = Date.parse(vulnerability.updatedAt);
  if (Number.isFinite(updatedAtMs)) {
    return updatedAtMs;
  }

  return getVulnerabilityFreshnessPublishedAtMs(vulnerability);
};

export const toRetentionRank = (record: {
  cacheKey: string;
  freshnessUpdatedAtMs: number;
  lastSeenAtMs: number;
}): readonly [number, number, string] => [
  record.lastSeenAtMs,
  record.freshnessUpdatedAtMs,
  record.cacheKey
];

export const createPersistedVulnerabilityRecord = (
  sourceId: string,
  vulnerability: Vulnerability,
  lastSeenAt: string,
  createdAtMs: number
): PersistedVulnerabilityRecord => {
  const cacheKey = buildPersistedVulnerabilityKey(sourceId, vulnerability.id);
  const freshnessUpdatedAtMs = getVulnerabilityFreshnessUpdatedAtMs(vulnerability);
  const freshnessPublishedAtMs = getVulnerabilityFreshnessPublishedAtMs(vulnerability);
  const lastSeenAtMs = Number.isFinite(Date.parse(lastSeenAt)) ? Date.parse(lastSeenAt) : createdAtMs;

  return {
    cacheKey,
    createdAtMs,
    freshnessPublishedAtMs,
    freshnessUpdatedAtMs,
    lastSeenAt,
    lastSeenAtMs,
    retentionRank: toRetentionRank({ cacheKey, freshnessUpdatedAtMs, lastSeenAtMs }),
    sourceId,
    vulnerability,
    vulnerabilityId: vulnerability.id
  };
};

export const comparePersistedRecordsForHardCap = (
  left: Pick<PersistedVulnerabilityRecord, 'cacheKey' | 'freshnessPublishedAtMs' | 'freshnessUpdatedAtMs' | 'lastSeenAtMs'>,
  right: Pick<PersistedVulnerabilityRecord, 'cacheKey' | 'freshnessPublishedAtMs' | 'freshnessUpdatedAtMs' | 'lastSeenAtMs'>
): number =>
  right.lastSeenAtMs - left.lastSeenAtMs
  || right.freshnessUpdatedAtMs - left.freshnessUpdatedAtMs
  || right.freshnessPublishedAtMs - left.freshnessPublishedAtMs
  || left.cacheKey.localeCompare(right.cacheKey);

export const applyVulnCacheSchemaUpgrade = (
  database: IDBDatabase | SchemaDatabase,
  _oldVersion: number,
  _newVersion: number | null
): void => {
  const vulnerabilities = ensureStore(database as SchemaDatabase, VULN_CACHE_STORES.vulnerabilities, {
    keyPath: 'cacheKey'
  });
  ensureIndex(vulnerabilities, VULN_CACHE_INDEXES.bySourceId, 'sourceId', { unique: false });
  ensureIndex(vulnerabilities, VULN_CACHE_INDEXES.byLastSeenAt, 'lastSeenAtMs', { unique: false });
  ensureIndex(vulnerabilities, VULN_CACHE_INDEXES.byRetentionRank, 'retentionRank', { unique: false });

  ensureStore(database as SchemaDatabase, VULN_CACHE_STORES.syncMetadata, {
    keyPath: 'sourceId'
  });
  ensureStore(database as SchemaDatabase, VULN_CACHE_STORES.databaseMetadata, {
    keyPath: 'key'
  });
};
