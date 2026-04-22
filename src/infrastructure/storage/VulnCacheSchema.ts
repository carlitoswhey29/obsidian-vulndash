import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { TriageRecord } from '../../domain/triage/TriageRecord';

export const VULN_CACHE_DB_NAME = 'vulndash-cache';
export const VULN_CACHE_DB_VERSION = 3;

export const VULN_CACHE_STORES = {
  componentQueries: 'componentQueries',
  databaseMetadata: 'database-metadata',
  syncMetadata: 'sync-metadata',
  triageRecords: 'triage-records',
  vulnerabilities: 'vulnerabilities'
} as const;

export const VULN_CACHE_INDEXES = {
  byLastSeenAt: 'by-last-seen-at',
  byRetentionRank: 'by-retention-rank',
  bySourceId: 'by-source-id',
  triageByState: 'triage-by-state',
  triageByUpdatedAt: 'triage-by-updated-at'
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

export interface PersistedComponentQueryRecord {
  readonly purl: string;
  readonly source: 'osv';
  readonly lastQueriedAtMs: number;
  readonly lastSeenInWorkspaceAtMs: number;
  readonly resultState: 'hit' | 'miss' | 'error';
  readonly vulnerabilityCacheKeys: readonly string[];
}

export interface PersistedTriageRecord {
  readonly correlationKey: string;
  readonly vulnerabilityId: string;
  readonly source: string;
  readonly state: string;
  readonly updatedAt: string;
  readonly updatedAtMs: number;
  readonly reason?: string;
  readonly ticketRef?: string;
  readonly updatedBy?: string;
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

export const createPersistedTriageRecord = (record: TriageRecord): PersistedTriageRecord => ({
  correlationKey: record.correlationKey,
  vulnerabilityId: record.vulnerabilityId,
  source: record.source,
  state: record.state,
  updatedAt: record.updatedAt,
  updatedAtMs: Number.isFinite(Date.parse(record.updatedAt)) ? Date.parse(record.updatedAt) : 0,
  ...(record.reason ? { reason: record.reason } : {}),
  ...(record.ticketRef ? { ticketRef: record.ticketRef } : {}),
  ...(record.updatedBy ? { updatedBy: record.updatedBy } : {})
});

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
  oldVersion: number,
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

  const triageRecords = ensureStore(database as SchemaDatabase, VULN_CACHE_STORES.triageRecords, {
    keyPath: 'correlationKey'
  });
  ensureIndex(triageRecords, VULN_CACHE_INDEXES.triageByState, 'state', { unique: false });
  ensureIndex(triageRecords, VULN_CACHE_INDEXES.triageByUpdatedAt, 'updatedAtMs', { unique: false });

  if (oldVersion < 3 || !database.objectStoreNames.contains(VULN_CACHE_STORES.componentQueries)) {
    ensureStore(database as SchemaDatabase, VULN_CACHE_STORES.componentQueries, {
      keyPath: 'purl'
    });
  }
};
