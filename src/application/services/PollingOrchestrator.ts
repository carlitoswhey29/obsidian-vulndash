import type { VulnerabilityFeed } from '../ports/VulnerabilityFeed';
import type { PipelineEventListener } from '../pipeline/PipelineEvents';
import type { PipelineConfig } from '../pipeline/PipelineTypes';
import { VulnerabilitySyncService, type SyncOutcome, type SyncState } from './VulnerabilitySyncService';
import type { SyncControls } from './types';

interface PollingOptions {
  readonly onPipelineEvent?: PipelineEventListener;
  readonly pipelineConfig?: Partial<PipelineConfig>;
}

export type { SyncOutcome, SyncResult } from './VulnerabilitySyncService';

export class PollingOrchestrator {
  private running = false;
  private readonly syncService: VulnerabilitySyncService;

  public constructor(
    feeds: VulnerabilityFeed[],
    controls: SyncControls,
    state: SyncState,
    options: PollingOptions = {}
  ) {
    this.syncService = new VulnerabilitySyncService({
      controls,
      feeds,
      ...(options.onPipelineEvent ? { onPipelineEvent: options.onPipelineEvent } : {}),
      ...(options.pipelineConfig ? { pipelineConfig: options.pipelineConfig } : {}),
      state
    });
  }

  public async pollOnce(): Promise<SyncOutcome> {
    return this.syncService.syncNow();
  }

  public start(intervalMs: number, callback: (outcome: SyncOutcome) => void): () => void {
    this.running = true;
    let timeoutHandle: number | null = null;

    const execute = async (): Promise<void> => {
      if (!this.running) {
        return;
      }

      const outcome = await this.pollOnce();
      callback(outcome);

      if (!this.running) {
        return;
      }

      timeoutHandle = window.setTimeout(() => {
        void execute();
      }, intervalMs);
    };

    void execute();

    return () => {
      this.running = false;
      if (timeoutHandle !== null) {
        window.clearTimeout(timeoutHandle);
      }
    };
  }
}

