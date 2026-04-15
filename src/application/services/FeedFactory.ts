import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';
import type { FeedConfig, SyncControls } from './types';
import type { IHttpClient } from '../ports/IHttpClient';
import { GitHubAdvisoryClient } from '../../infrastructure/clients/github/GitHubAdvisoryClient';
import { GitHubRepoClient } from '../../infrastructure/clients/github/GitHubRepoClient';
import { NvdClient } from '../../infrastructure/clients/nvd/NvdClient';
import { GenericJsonFeedClient } from '../../infrastructure/api/GenericJsonFeedClient';

export const buildFeedsFromConfig = (
  configs: FeedConfig[],
  httpClient: IHttpClient,
  controls: SyncControls
): VulnerabilityFeed[] => {
  const feeds: VulnerabilityFeed[] = [];

  for (const config of configs) {
    if (!config.enabled) {
      continue;
    }

    switch (config.type) {
      case 'nvd': {
        feeds.push(new NvdClient(httpClient, config.id, config.name, config.apiKey ?? config.token ?? '', controls));
        break;
      }
      case 'github_advisory': {
        feeds.push(new GitHubAdvisoryClient(httpClient, config.id, config.name, config.token ?? '', controls));
        break;
      }
      case 'github_repo': {
        const repoPath = config.repoPath.trim();
        if (!repoPath) {
          console.warn('[vulndash.feed.invalid]', { id: config.id, type: config.type, reason: 'missing_repo_path' });
          break;
        }
        feeds.push(new GitHubRepoClient(httpClient, config.id, config.name, config.token ?? '', repoPath, controls));
        break;
      }
      case 'generic_json': {
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
      default: {
        const unreachable: never = config;
        console.warn('[vulndash.feed.unknown]', unreachable);
      }
    }
  }

  return feeds;
};
