import type { AffectedProjectResolution } from '../correlation/AffectedProjectResolution';
import type { TriageState } from '../triage/TriageState';
import type { Severity } from '../value-objects/Severity';
import { severityOrder } from '../value-objects/Severity';

export interface DailyRollupPolicyProps {
  readonly excludedTriageStates: readonly TriageState[];
  readonly includeUnmappedFindings: boolean;
  readonly severityThreshold: Severity;
}

export class DailyRollupPolicy {
  private readonly excludedTriageStates: ReadonlySet<TriageState>;
  private readonly includeUnmappedFindings: boolean;
  private readonly severityThreshold: Severity;

  public constructor(props: DailyRollupPolicyProps) {
    this.excludedTriageStates = new Set(props.excludedTriageStates);
    this.includeUnmappedFindings = props.includeUnmappedFindings;
    this.severityThreshold = props.severityThreshold;
  }

  public shouldInclude(input: {
    readonly resolution: AffectedProjectResolution;
    readonly severity: Severity;
    readonly triageState: TriageState;
  }): boolean {
    if (severityOrder[input.severity] < severityOrder[this.severityThreshold]) {
      return false;
    }

    if (this.excludedTriageStates.has(input.triageState)) {
      return false;
    }

    if (input.resolution.affectedProjects.length > 0) {
      return true;
    }

    return this.includeUnmappedFindings && input.resolution.unmappedSboms.length > 0;
  }

  public toJSON(): DailyRollupPolicyProps {
    return {
      excludedTriageStates: Array.from(this.excludedTriageStates),
      includeUnmappedFindings: this.includeUnmappedFindings,
      severityThreshold: this.severityThreshold
    };
  }
}
