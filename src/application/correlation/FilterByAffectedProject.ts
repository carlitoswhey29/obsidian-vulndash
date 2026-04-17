import type { Vulnerability } from '../../domain/entities/Vulnerability';
import {
  EMPTY_AFFECTED_PROJECT_RESOLUTION,
  type AffectedProjectResolution
} from '../../domain/correlation/AffectedProjectResolution';

export type AffectedProjectFilter =
  | { readonly kind: 'all'; }
  | { readonly kind: 'project'; readonly notePath: string; }
  | { readonly kind: 'unmapped'; };

export const ALL_AFFECTED_PROJECT_FILTER: AffectedProjectFilter = { kind: 'all' };
export const UNMAPPED_AFFECTED_PROJECT_FILTER: AffectedProjectFilter = { kind: 'unmapped' };

export class FilterByAffectedProject {
  public execute(
    vulnerabilities: readonly Vulnerability[],
    filter: AffectedProjectFilter,
    getResolution: (vulnerability: Vulnerability) => AffectedProjectResolution
  ): Vulnerability[] {
    if (filter.kind === 'all') {
      return [...vulnerabilities];
    }

    return vulnerabilities.filter((vulnerability) => {
      const resolution = getResolution(vulnerability) ?? EMPTY_AFFECTED_PROJECT_RESOLUTION;
      if (filter.kind === 'unmapped') {
        return resolution.unmappedSboms.length > 0;
      }

      return resolution.affectedProjects.some((project) => project.notePath === filter.notePath);
    });
  }
}
