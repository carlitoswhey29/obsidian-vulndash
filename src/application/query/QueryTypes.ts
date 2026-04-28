import type { AffectedProjectFilter } from '../correlation/FilterByAffectedProject';
import type { DashboardDateRangeSelection } from '../dashboard/PublishedDateWindow';
import type { DashboardDateField } from '../use-cases/types';
import type { AffectedProjectResolution } from '../../domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { Severity } from '../../domain/value-objects/Severity';

export type VulnerabilityQuerySortField = 'id' | 'title' | 'source' | 'severity' | 'cvssScore' | 'publishedAt';
export type VulnerabilityQuerySortDirection = 'asc' | 'desc';

export interface VulnerabilityDateQuery {
  readonly field: DashboardDateField;
  readonly now?: Date;
  readonly range: DashboardDateRangeSelection;
}

export interface VulnerabilityQuery {
  readonly affectedProject?: AffectedProjectFilter;
  readonly date?: VulnerabilityDateQuery;
  readonly limit?: number;
  readonly searchText?: string;
  readonly severities?: readonly Severity[];
  readonly sort: {
    readonly direction: VulnerabilityQuerySortDirection;
    readonly field: VulnerabilityQuerySortField;
  };
}

export interface VulnerabilityQueryDataset {
  readonly getAffectedProjectResolution: (vulnerability: Vulnerability) => AffectedProjectResolution;
  readonly vulnerabilities: readonly Vulnerability[];
}
