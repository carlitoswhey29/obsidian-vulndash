import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';

const sleep = async (ms: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, ms));
};

export class PollingOrchestrator {
  private running = false;

  public constructor(private readonly feeds: VulnerabilityFeed[]) {}

  public async pollOnce(): Promise<Vulnerability[]> {
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
      } catch (error) {
        if (attempt === 4) return [];
        await sleep(delay);
        delay = Math.min(delay * 2, 30_000);
      }
    }
    return [];
  }
}
