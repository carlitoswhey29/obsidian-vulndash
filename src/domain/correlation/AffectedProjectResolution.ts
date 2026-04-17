export type ResolvedAffectedProjectStatus = 'broken' | 'linked';

export interface ResolvedAffectedProject {
  readonly displayName: string;
  readonly notePath: string;
  readonly sourceSbomIds: readonly string[];
  readonly sourceSbomLabels: readonly string[];
  readonly status: ResolvedAffectedProjectStatus;
}

export interface UnmappedAffectedSbom {
  readonly sbomId: string;
  readonly sbomLabel: string;
}

export interface AffectedProjectResolution {
  readonly affectedProjects: readonly ResolvedAffectedProject[];
  readonly unmappedSboms: readonly UnmappedAffectedSbom[];
}

export const EMPTY_AFFECTED_PROJECT_RESOLUTION: AffectedProjectResolution = {
  affectedProjects: [],
  unmappedSboms: []
};
