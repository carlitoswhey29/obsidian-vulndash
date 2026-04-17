import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { DEFAULT_TRIAGE_STATE, type TriageState } from '../../domain/triage/TriageState';
import { FilterByTriageState } from '../triage/FilterByTriageState';
import type { VulnDashSettings } from './types';
import { severityOrder } from '../../domain/value-objects/Severity';

export interface AlertEngineOptions {
  readonly getTriageState?: (vulnerability: Vulnerability) => TriageState | undefined;
}

export class AlertEngine {
  private readonly triageFilter = new FilterByTriageState();

  /**
   * Applies user-configured filtering rules in a deterministic order:
   * 1) numeric thresholds, 2) product filters, 3) keyword/regex filters, 4) triage state.
   */
  public filter(
    vulnerabilities: Vulnerability[],
    settings: VulnDashSettings,
    options: AlertEngineOptions = {}
  ): Vulnerability[] {
    const keywords = settings.keywordFilters.map((value) => value.toLowerCase());
    const products = settings.productFilters.map((value) => value.toLowerCase());
    const minSeverityRank = severityOrder[settings.minSeverity];
    const regexFilters = settings.keywordRegexEnabled ? this.getRegexFilters(settings.keywordFilters) : [];

    const filtered = vulnerabilities.filter((vuln) => {
      if (vuln.cvssScore < settings.minCvssScore) return false;
      if (severityOrder[vuln.severity] < minSeverityRank) return false;

      const haystack = `${vuln.title} ${vuln.summary}`.toLowerCase();
      const productMatch = products.length === 0
        || vuln.affectedProducts.some((product) => products.some((filter) => product.toLowerCase().includes(filter)));
      const keywordMatch = settings.keywordRegexEnabled
        ? regexFilters.length === 0 || regexFilters.some((keyword) => keyword.test(`${vuln.title} ${vuln.summary}`))
        : keywords.length === 0 || keywords.some((keyword) => haystack.includes(keyword));

      return keywordMatch && productMatch;
    });

    const triageMode = settings.triageFilter;
    if (triageMode === 'all') {
      return filtered;
    }

    const triageAware = filtered.map((vulnerability) => ({
      triageState: options.getTriageState?.(vulnerability) ?? DEFAULT_TRIAGE_STATE,
      vulnerability
    }));

    return this.triageFilter.execute(triageAware, triageMode).map((entry) => entry.vulnerability);
  }

  /**
   * Compiles case-insensitive regex filters from user input.
   * Invalid patterns are ignored so one bad rule does not disable filtering.
   */
  private getRegexFilters(filters: string[]): RegExp[] {
    const regexFilters: RegExp[] = [];
    for (const filter of filters) {
      try {
        regexFilters.push(new RegExp(filter, 'i'));
      } catch {
        // Ignore invalid user-provided regex.
      }
    }

    return regexFilters;
  }
}
