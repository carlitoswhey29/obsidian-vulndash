import { buildPersistedVulnerabilityKey } from '../../storage/VulnCacheSchema';

const DEFAULT_OSV_CACHE_SOURCE_ID = 'osv';

export const buildOsvVulnerabilityCacheKey = (vulnerabilityId: string, sourceId = DEFAULT_OSV_CACHE_SOURCE_ID): string =>
  buildPersistedVulnerabilityKey(sourceId, vulnerabilityId);
