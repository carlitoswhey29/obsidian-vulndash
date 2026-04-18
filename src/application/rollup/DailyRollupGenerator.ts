import { DailyRollupPolicy } from '../../domain/rollup/DailyRollupPolicy';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { DailyRollupSettings } from '../use-cases/types';
import { RollupMarkdownRenderer, type RenderedDailyRollup } from './RollupMarkdownRenderer';
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
    private readonly writer: DailyRollupWriter
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
    const document = this.renderer.render({
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
}
