import { buildPersistedVulnerabilityKey } from '../../storage/VulnCacheSchema';
import { BUILT_IN_FEEDS } from '../../../domain/feeds/FeedTypes';

const DEFAULT_OSV_CACHE_SOURCE_ID = BUILT_IN_FEEDS.OSV.type;

export const buildOsvVulnerabilityCacheKey = (
  vulnerabilityId: string,
  sourceId: string = DEFAULT_OSV_CACHE_SOURCE_ID
): string =>
  buildPersistedVulnerabilityKey(sourceId, vulnerabilityId);
