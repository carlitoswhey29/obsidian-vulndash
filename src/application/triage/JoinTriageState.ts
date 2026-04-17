import { buildVulnerabilityCacheKey } from '../pipeline/PipelineTypes';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { buildTriageCorrelationKeyForVulnerability } from '../../domain/triage/TriageCorrelation';
import type { TriageRecord } from '../../domain/triage/TriageRecord';
import type { TriageRepository } from '../../domain/triage/TriageRepository';
import { DEFAULT_TRIAGE_STATE, type TriageState } from '../../domain/triage/TriageState';

export interface JoinedTriageVulnerability {
  readonly cacheKey: string;
  readonly correlationKey: string;
  readonly triageRecord: TriageRecord | null;
  readonly triageState: TriageState;
  readonly vulnerability: Vulnerability;
}

export class JoinTriageState {
  public constructor(
    private readonly repository: TriageRepository
  ) {}

  public async execute(vulnerabilities: readonly Vulnerability[]): Promise<readonly JoinedTriageVulnerability[]> {
    const correlationKeys = Array.from(new Set(vulnerabilities.map((vulnerability) =>
      buildTriageCorrelationKeyForVulnerability(vulnerability)
    )));
    const triageByCorrelationKey = await this.repository.getByCorrelationKeys(correlationKeys);

    return vulnerabilities.map((vulnerability) => {
      const correlationKey = buildTriageCorrelationKeyForVulnerability(vulnerability);
      const triageRecord = triageByCorrelationKey.get(correlationKey) ?? null;

      return {
        cacheKey: buildVulnerabilityCacheKey(vulnerability),
        correlationKey,
        triageRecord,
        triageState: triageRecord?.state ?? DEFAULT_TRIAGE_STATE,
        vulnerability
      };
    });
  }
}
