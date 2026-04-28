import type { VulnerabilityFeed } from '../../application/ports/VulnerabilityFeed';
import type { FeedConfig, SyncControls } from '../../application/use-cases/types';
import type { IHttpClient } from '../../application/ports/HttpClient';
import { FEED_TYPES } from '../../domain/feeds/FeedTypes';
import { GitHubAdvisoryClient } from '../clients/github/GitHubAdvisoryClient';
import { GitHubRepoClient } from '../clients/github/GitHubRepoClient';
import { GenericJsonFeedClient } from '../clients/generic/GenericJsonFeedClient';
import { NvdClient } from '../clients/nvd/NvdClient';
import { OsvFeedClient } from '../clients/osv/OsvFeedClient';
import type { IOsvQueryCache } from '../clients/osv/IOsvQueryCache';

export interface FeedFactoryDependencies {
  readonly getPurls?: () => Promise<readonly string[]>;
  readonly osvQueryCache?: IOsvQueryCache;
}

export const buildFeedsFromConfig = (
  configs: FeedConfig[],
  httpClient: IHttpClient,
  controls: SyncControls,
  dependencies: FeedFactoryDependencies = {}
): VulnerabilityFeed[] => {
  const feeds: VulnerabilityFeed[] = [];

  for (const config of configs) {
    if (!config.enabled) {
      continue;
    }

    switch (config.type) {
      case FEED_TYPES.NVD: {
        feeds.push(new NvdClient(
          httpClient,
          config.id,
          config.name,
          config.apiKey ?? config.token ?? '',
          controls,
          config.dateFilterType // Pass the setting here
        ));
        break;
      }
      case FEED_TYPES.GITHUB_ADVISORY: {
        feeds.push(new GitHubAdvisoryClient(httpClient, config.id, config.name, config.token ?? '', controls));
        break;
      }
      case FEED_TYPES.GITHUB_REPO: {
        const repoPath = config.repoPath.trim();
        if (!repoPath) {
          console.warn('[vulndash.feed.invalid]', { id: config.id, type: config.type, reason: 'missing_repo_path' });
          break;
        }
        feeds.push(new GitHubRepoClient(httpClient, config.id, config.name, config.token ?? '', repoPath, controls));
        break;
      }
      case FEED_TYPES.GENERIC_JSON: {
        const url = config.url.trim();
        if (!url) {
          console.warn('[vulndash.feed.invalid]', { id: config.id, type: config.type, reason: 'missing_url' });
          break;
        }
        feeds.push(new GenericJsonFeedClient(
          httpClient,
          config.id,
          config.name,
          url,
          config.token ?? '',
          config.authHeaderName ?? 'Authorization',
          controls
        ));
        break;
      }
      case FEED_TYPES.OSV: {
        if (!dependencies.osvQueryCache || !dependencies.getPurls) {
          console.warn('[vulndash.feed.invalid]', { id: config.id, type: config.type, reason: 'missing_osv_dependencies' });
          break;
        }

        feeds.push(new OsvFeedClient(
          httpClient,
          dependencies.osvQueryCache,
          dependencies.getPurls,
          controls,
          config
        ));
        break;
      }
      default: {
        const unreachable: never = config;
        console.warn('[vulndash.feed.unknown]', unreachable);
      }
    }
  }

  return feeds;
};
