import { buildVulnerabilityCacheKey } from '../pipeline/PipelineTypes';
import { RelationshipNormalizer } from '../sbom/RelationshipNormalizer';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { DailyRollupPolicy } from '../../domain/rollup/DailyRollupPolicy';
import type { RollupFinding } from '../../domain/rollup/RollupFinding';
import type { TriageRecord } from '../../domain/triage/TriageRecord';
import { DEFAULT_TRIAGE_STATE, type TriageState } from '../../domain/triage/TriageState';
import { severityOrder } from '../../domain/value-objects/Severity';

export interface RollupTriageSnapshot {
  readonly record: TriageRecord | null;
  readonly state: TriageState;
}

const compareFindings = (left: RollupFinding, right: RollupFinding): number =>
  severityOrder[right.vulnerability.severity] - severityOrder[left.vulnerability.severity]
  || right.vulnerability.updatedAt.localeCompare(left.vulnerability.updatedAt)
  || right.vulnerability.publishedAt.localeCompare(left.vulnerability.publishedAt)
  || left.vulnerability.source.localeCompare(right.vulnerability.source)
  || left.vulnerability.id.localeCompare(right.vulnerability.id);

export class SelectRollupFindings {
  public constructor(
    private readonly relationshipNormalizer = new RelationshipNormalizer()
  ) {}

  public execute(input: {
    readonly affectedProjectsByVulnerabilityRef: ReadonlyMap<string, AffectedProjectResolution>;
    readonly policy: DailyRollupPolicy;
    readonly triageByCacheKey: ReadonlyMap<string, RollupTriageSnapshot>;
    readonly vulnerabilities: readonly Vulnerability[];
  }): RollupFinding[] {
    const findingsByKey = new Map<string, RollupFinding>();

    for (const vulnerability of input.vulnerabilities) {
      const key = buildVulnerabilityCacheKey(vulnerability);
      if (findingsByKey.has(key)) {
        continue;
      }

      const triage = input.triageByCacheKey.get(key) ?? {
        record: null,
        state: DEFAULT_TRIAGE_STATE
      } satisfies RollupTriageSnapshot;
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
      const resolution = input.affectedProjectsByVulnerabilityRef.get(vulnerabilityRef) ?? {
        affectedProjects: [],
        unmappedSboms: []
      } satisfies AffectedProjectResolution;

      if (!input.policy.shouldInclude({
        resolution,
        severity: vulnerability.severity,
        triageState: triage.state
      })) {
        continue;
      }

      findingsByKey.set(key, {
        affectedProjects: resolution.affectedProjects,
        key,
        triageRecord: triage.record,
        triageState: triage.state,
        unmappedSboms: resolution.unmappedSboms,
        vulnerability
      });
    }

    return Array.from(findingsByKey.values()).sort(compareFindings);
  }
}
