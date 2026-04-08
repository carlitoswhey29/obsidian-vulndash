import type { SecretProvider, VulnerabilityFeed } from '../ports/VulnerabilityFeed';
import type { FeedConfig, SyncControls } from './types';
import type { IHttpClient } from '../ports/IHttpClient';
import { GitHubAdvisoryClient } from '../../infrastructure/api/GitHubAdvisoryClient';
import { GitHubRepoClient } from '../../infrastructure/api/GitHubRepoClient';
import { NvdClient } from '../../infrastructure/api/NvdClient';
import { GenericJsonFeedClient } from '../../infrastructure/api/GenericJsonFeedClient';
import { logger } from '../../infrastructure/utils/logger';

export const buildFeedsFromConfig = (
  configs: FeedConfig[],
  httpClient: IHttpClient,
  controls: SyncControls,
  resolveSecret: (secret: string) => Promise<string> = async (secret) => secret
): VulnerabilityFeed[] => {
  const feeds: VulnerabilityFeed[] = [];
  const secretProvider = (secret: string | undefined): SecretProvider => async () => resolveSecret(secret ?? '');

  for (const config of configs) {
    if (!config.enabled) {
      continue;
    }

    switch (config.type) {
      case 'nvd': {
        feeds.push(new NvdClient(httpClient, config.id, config.name, secretProvider(config.apiKey ?? config.token), controls));
        break;
      }
      case 'github_advisory': {
        feeds.push(new GitHubAdvisoryClient(httpClient, config.id, config.name, secretProvider(config.token), controls));
        break;
      }
      case 'github_repo': {
        const repoPath = config.repoPath.trim();
        if (!repoPath) {
          logger.warn('[vulndash.feed.invalid]', { id: config.id, type: config.type, reason: 'missing_repo_path' });
          break;
        }
        feeds.push(new GitHubRepoClient(httpClient, config.id, config.name, secretProvider(config.token), repoPath, controls));
        break;
      }
      case 'generic_json': {
        const url = config.url.trim();
        if (!url) {
          logger.warn('[vulndash.feed.invalid]', { id: config.id, type: config.type, reason: 'missing_url' });
          break;
        }
        feeds.push(new GenericJsonFeedClient(
          httpClient,
          config.id,
          config.name,
          url,
          secretProvider(config.token),
          config.authHeaderName ?? 'Authorization',
          controls
        ));
        break;
      }
      default: {
        const unreachable: never = config;
        logger.warn('[vulndash.feed.unknown]', unreachable);
      }
    }
  }

  return feeds;
};
