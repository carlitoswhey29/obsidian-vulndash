import { buildPersistedVulnerabilityKey } from '../../storage/VulnCacheSchema';

const OSV_CACHE_SOURCE_ID = 'osv';

export const buildOsvVulnerabilityCacheKey = (vulnerabilityId: string): string =>
  buildPersistedVulnerabilityKey(OSV_CACHE_SOURCE_ID, vulnerabilityId);
