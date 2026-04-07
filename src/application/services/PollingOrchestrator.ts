import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { HttpRequestError } from '../ports/HttpRequestError';
import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';

const sleep = async (ms: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

export class PollingOrchestrator {
  private running = false;

  public constructor(private readonly feeds: VulnerabilityFeed[]) {}

  public async pollOnce(): Promise<Vulnerability[]> {
    // Poll all feeds independently so one outage does not block other sources.
    const results = await Promise.allSettled(
      this.feeds.map(async (feed) => {
        const controller = new AbortController();
        return this.fetchWithBackoff(feed, controller.signal);
      })
    );

    const merged: Vulnerability[] = [];
    for (const result of results) {
      if (result.status === 'fulfilled') {
        merged.push(...result.value);
      }
    }

    return merged.sort((a, b) => b.publishedAt.localeCompare(a.publishedAt));
  }

  public start(intervalMs: number, callback: (vulns: Vulnerability[]) => void): () => void {
    this.running = true;

    const execute = async (): Promise<void> => {
      if (!this.running) return;
      const vulns = await this.pollOnce();
      callback(vulns);
      if (this.running) {
        // setTimeout avoids overlapping polls if the previous cycle runs long.
        window.setTimeout(() => {
          void execute();
        }, intervalMs);
      }
    };

    void execute();

    return () => {
      this.running = false;
    };
  }

  private async fetchWithBackoff(feed: VulnerabilityFeed, signal: AbortSignal): Promise<Vulnerability[]> {
    let delay = 1_000;
    for (let attempt = 1; attempt <= 4; attempt += 1) {
      try {
        return await feed.fetchVulnerabilities(signal);
      } catch (error: unknown) {
        if (error instanceof HttpRequestError) {
          console.warn(
            `Error fetching from ${feed.name} (attempt ${attempt}): ${error.message}`
          );
          if (!error.retryable) {
            return [];
          }
          if (attempt === 4) {
            return [];
          }
          const nextDelay = error.retryAfterMs ?? delay;
          await sleep(nextDelay);
          delay = Math.min(delay * 2, 30_000);
          continue;
        }

        if (error instanceof Error) {
          console.warn(`Error fetching from ${feed.name} (attempt ${attempt}): ${error.message}`);
        } else {
          console.warn(`Unknown error fetching from ${feed.name} (attempt ${attempt})`);
        }
        if (attempt === 4) return [];
        // Exponential backoff reduces pressure on remote APIs during transient failures.
        await sleep(delay);
        delay = Math.min(delay * 2, 30_000);
      }
    }
    return [];
  }
}
