import type { PipelineRunId } from './PipelineTypes';

export interface RegisteredPipelineRun {
  readonly generation: number;
  readonly runId: PipelineRunId;
  readonly sourceId: string;
}

export class PipelineRunRegistry {
  private readonly activeRunIds = new Map<string, PipelineRunId>();
  private readonly generations = new Map<string, number>();

  public start(sourceId: string): RegisteredPipelineRun {
    const nextGeneration = (this.generations.get(sourceId) ?? 0) + 1;
    this.generations.set(sourceId, nextGeneration);

    const runId = `${sourceId}:${nextGeneration}` as PipelineRunId;
    this.activeRunIds.set(sourceId, runId);

    return {
      generation: nextGeneration,
      runId,
      sourceId
    };
  }

  public isCurrent(run: RegisteredPipelineRun): boolean {
    return this.activeRunIds.get(run.sourceId) === run.runId;
  }

  public finish(run: RegisteredPipelineRun): void {
    if (this.activeRunIds.get(run.sourceId) === run.runId) {
      this.activeRunIds.delete(run.sourceId);
    }
  }
}
