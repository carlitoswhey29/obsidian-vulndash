import type { RenderDailyRollupInput, RenderedDailyRollup } from '../../application/rollup/RollupMarkdownRenderer';
import type { NormalizedVulnerabilityBatch, PipelineBatchInput } from '../../application/pipeline/PipelineTypes';
import type { NormalizedSbomDocument } from '../../domain/sbom/types';

export type AsyncTaskKind = 'normalize-vulnerabilities' | 'parse-sbom' | 'render-daily-rollup';

export interface AsyncTaskToken {
  readonly generation: number;
  readonly key: string;
}

export interface SbomParseTaskSource {
  readonly basename: string;
  readonly path: string;
}

export interface ParseSbomTaskRequest {
  readonly raw: string;
  readonly source: SbomParseTaskSource;
}

export interface ParseSbomTaskResult {
  readonly document: NormalizedSbomDocument;
}

export interface NormalizeVulnerabilityTaskRequest {
  readonly input: PipelineBatchInput;
}

export interface NormalizeVulnerabilityTaskResult {
  readonly batch: NormalizedVulnerabilityBatch;
}

export type RenderDailyRollupTaskRequest = RenderDailyRollupInput;

export interface RenderDailyRollupTaskResult {
  readonly document: RenderedDailyRollup;
}

export interface AsyncTaskPayloadByKind {
  readonly 'normalize-vulnerabilities': NormalizeVulnerabilityTaskRequest;
  readonly 'parse-sbom': ParseSbomTaskRequest;
  readonly 'render-daily-rollup': RenderDailyRollupTaskRequest;
}

export interface AsyncTaskResultByKind {
  readonly 'normalize-vulnerabilities': NormalizeVulnerabilityTaskResult;
  readonly 'parse-sbom': ParseSbomTaskResult;
  readonly 'render-daily-rollup': RenderDailyRollupTaskResult;
}

export interface AsyncTaskRequestMessage<K extends AsyncTaskKind = AsyncTaskKind> {
  readonly payload: AsyncTaskPayloadByKind[K];
  readonly requestId: number;
  readonly taskKind: K;
}

export interface AsyncTaskSuccessMessage<K extends AsyncTaskKind = AsyncTaskKind> {
  readonly requestId: number;
  readonly result: AsyncTaskResultByKind[K];
  readonly success: true;
  readonly taskKind: K;
}

export interface AsyncTaskFailureMessage<K extends AsyncTaskKind = AsyncTaskKind> {
  readonly error: string;
  readonly requestId: number;
  readonly success: false;
  readonly taskKind: K;
}

export type AsyncTaskResponseMessage<K extends AsyncTaskKind = AsyncTaskKind> =
  | AsyncTaskFailureMessage<K>
  | AsyncTaskSuccessMessage<K>;
