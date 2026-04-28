import {
  ALL_AFFECTED_PROJECT_FILTER,
  FilterByAffectedProject
} from '../correlation/FilterByAffectedProject';
import {
  filterVulnerabilitiesByDateWindow,
  resolveDashboardDateRangeSelection
} from '../dashboard/PublishedDateWindow';
import { buildVulnerabilityCacheKey } from '../pipeline/PipelineTypes';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { severityOrder } from '../../domain/value-objects/Severity';
import type {
  VulnerabilityQuery,
  VulnerabilityQueryDataset,
  VulnerabilityQuerySortField
} from './QueryTypes';

const compareStrings = (left: string, right: string): number => left.localeCompare(right);
const compareNumbers = (left: number, right: number): number => left - right;

export class VulnQueryEngine {
  private readonly affectedProjectFilter = new FilterByAffectedProject();

  public execute(dataset: VulnerabilityQueryDataset, query: VulnerabilityQuery): Vulnerability[] {
    let data = [...dataset.vulnerabilities];

    if (query.date) {
      const dateRangeResolution = resolveDashboardDateRangeSelection(query.date.range, query.date.now);
      if (dateRangeResolution.window) {
        data = filterVulnerabilitiesByDateWindow(data, dateRangeResolution.window, query.date.field);
      }
    }

    if (query.severities && query.severities.length > 0) {
      const severityFilter = new Set(query.severities);
      data = data.filter((vulnerability) => severityFilter.has(vulnerability.severity));
    }

    data = this.affectedProjectFilter.execute(
      data,
      query.affectedProject ?? ALL_AFFECTED_PROJECT_FILTER,
      dataset.getAffectedProjectResolution
    );

    if (query.searchText) {
      const searchText = query.searchText.toLowerCase();
      data = data.filter((vulnerability) => this.matchesSearchText(vulnerability, searchText));
    }

    data.sort((left, right) => {
      const comparison = this.compareVulnerabilities(left, right, query.sort.field);
      if (comparison !== 0) {
        return query.sort.direction === 'desc' ? -comparison : comparison;
      }

      return 0;
    });

    if (query.limit === undefined) {
      return data;
    }

    return data.slice(0, Math.max(query.limit, 0));
  }

  private matchesSearchText(vulnerability: Vulnerability, searchText: string): boolean {
    return vulnerability.title.toLowerCase().includes(searchText)
      || vulnerability.id.toLowerCase().includes(searchText)
      || vulnerability.source.toLowerCase().includes(searchText);
  }

  private compareVulnerabilities(
    left: Vulnerability,
    right: Vulnerability,
    sortField: VulnerabilityQuerySortField
  ): number {
    const primary = (() => {
      switch (sortField) {
        case 'severity':
          return compareNumbers(severityOrder[left.severity], severityOrder[right.severity]);
        case 'cvssScore':
          return compareNumbers(left.cvssScore, right.cvssScore);
        case 'id':
          return compareStrings(left.id, right.id);
        case 'source':
          return compareStrings(left.source, right.source);
        case 'title':
          return compareStrings(left.title, right.title);
        case 'publishedAt':
        default:
          return compareStrings(left.publishedAt, right.publishedAt);
      }
    })();

    if (primary !== 0) {
      return primary;
    }

    return compareStrings(buildVulnerabilityCacheKey(left), buildVulnerabilityCacheKey(right));
  }
}
