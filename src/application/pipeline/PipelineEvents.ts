import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type {
  ChangedVulnerabilityIds,
  NormalizedVulnerabilityBatch,
  PipelineBatchInput,
  PipelineMergeResult,
  PipelineProgressEvent
} from './PipelineTypes';

interface PipelineEventBase extends PipelineProgressEvent {
  readonly existingCursor?: string;
  readonly since?: string;
  readonly until: string;
}

export interface PipelineFetchEvent extends PipelineEventBase {
  readonly pagesFetched: number;
  readonly retriesPerformed: number;
  readonly stage: 'fetch';
  readonly warnings: readonly string[];
}

export interface PipelineTransformEvent extends PipelineEventBase {
  readonly batch: NormalizedVulnerabilityBatch;
  readonly input: PipelineBatchInput;
  readonly stage: 'transform';
}

export interface PipelineMergeEvent extends PipelineEventBase {
  readonly mergeResult: PipelineMergeResult;
  readonly stage: 'merge';
}

export interface PipelineNotifyEvent extends PipelineEventBase {
  readonly changedIds: ChangedVulnerabilityIds;
  readonly stage: 'notify';
  readonly vulnerabilities: readonly Vulnerability[];
}

export type PipelineEvent =
  | PipelineFetchEvent
  | PipelineTransformEvent
  | PipelineMergeEvent
  | PipelineNotifyEvent;

export type PipelineEventListener = (event: PipelineEvent) => void | Promise<void>;
