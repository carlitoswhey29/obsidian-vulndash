import { DailyRollupPolicy } from '../../domain/rollup/DailyRollupPolicy';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { AsyncTaskCoordinator } from '../../infrastructure/async/AsyncTaskCoordinator';
import type { DailyRollupSettings } from '../use-cases/types';
import {
  RollupMarkdownRenderer,
  type RenderDailyRollupInput,
  type RenderedDailyRollup
} from './RollupMarkdownRenderer';
import type { RollupTriageSnapshot } from './SelectRollupFindings';
import { SelectRollupFindings } from './SelectRollupFindings';

export interface DailyRollupWriter {
  write(input: {
    readonly date: string;
    readonly document: RenderedDailyRollup;
    readonly folderPath: string;
  }): Promise<{
    readonly content: string;
    readonly created: boolean;
    readonly path: string;
  }>;
}

export interface DailyRollupGenerationResult {
  readonly content: string;
  readonly date: string;
  readonly findingsCount: number;
  readonly path: string;
}

export class DailyRollupGenerator {
  public constructor(
    private readonly selectFindings: SelectRollupFindings,
    private readonly renderer: RollupMarkdownRenderer,
    private readonly writer: DailyRollupWriter,
    private readonly asyncTaskCoordinator = new AsyncTaskCoordinator()
  ) {}

  public async execute(input: {
    readonly affectedProjectsByVulnerabilityRef: ReadonlyMap<string, AffectedProjectResolution>;
    readonly date: string;
    readonly settings: DailyRollupSettings;
    readonly triageByCacheKey: ReadonlyMap<string, RollupTriageSnapshot>;
    readonly vulnerabilities: readonly Vulnerability[];
  }): Promise<DailyRollupGenerationResult> {
    const findings = this.selectFindings.execute({
      affectedProjectsByVulnerabilityRef: input.affectedProjectsByVulnerabilityRef,
      policy: new DailyRollupPolicy({
        excludedTriageStates: input.settings.excludedTriageStates,
        includeUnmappedFindings: input.settings.includeUnmappedFindings,
        severityThreshold: input.settings.severityThreshold
      }),
      triageByCacheKey: input.triageByCacheKey,
      vulnerabilities: input.vulnerabilities
    });
    const document = await this.renderDocument({
      date: input.date,
      findings
    });
    const written = await this.writer.write({
      date: input.date,
      document,
      folderPath: input.settings.folderPath
    });

    return {
      content: written.content,
      date: input.date,
      findingsCount: findings.length,
      path: written.path
    };
  }

  private async renderDocument(input: RenderDailyRollupInput): Promise<RenderedDailyRollup> {
    const rendered = await this.asyncTaskCoordinator.execute('render-daily-rollup', input, {
      fallback: async (payload, scheduler) => {
        await scheduler.yieldToHost({ timeoutMs: 16 });

        return {
          document: this.renderer.render(payload)
        };
      },
      preferWorker: input.findings.length > 0
    });

    return rendered.document;
  }
}
