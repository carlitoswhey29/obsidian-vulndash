import type {
  ResolvedAffectedProject,
  UnmappedAffectedSbom
} from '../correlation/AffectedProjectResolution';
import type { Vulnerability } from '../entities/Vulnerability';
import type { TriageRecord } from '../triage/TriageRecord';
import type { TriageState } from '../triage/TriageState';

export interface RollupFinding {
  readonly affectedProjects: readonly ResolvedAffectedProject[];
  readonly key: string;
  readonly triageRecord: TriageRecord | null;
  readonly triageState: TriageState;
  readonly unmappedSboms: readonly UnmappedAffectedSbom[];
  readonly vulnerability: Vulnerability;
}
