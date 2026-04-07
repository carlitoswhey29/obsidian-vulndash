import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { severityOrder } from '../../domain/entities/Severity';
import type { VulnDashSettings } from './types';

export class AlertEngine {
  /**
   * Applies user-configured filtering rules in a deterministic order:
   * 1) numeric thresholds, 2) product filters, 3) keyword/regex filters.
   */
  public filter(vulnerabilities: Vulnerability[], settings: VulnDashSettings): Vulnerability[] {
    const keywords = settings.keywordFilters.map((v) => v.toLowerCase());
    const products = settings.productFilters.map((v) => v.toLowerCase());
    const minSeverityRank = severityOrder[settings.minSeverity];
    const regexFilters = settings.keywordRegexEnabled ? this.getRegexFilters(settings.keywordFilters) : [];

    return vulnerabilities.filter((vuln) => {
      if (vuln.cvssScore < settings.minCvssScore) return false;
      if (severityOrder[vuln.severity] < minSeverityRank) return false;

      const haystack = `${vuln.title} ${vuln.summary}`.toLowerCase();
      const productMatch = products.length === 0
        || vuln.affectedProducts.some((p) => products.some((filter) => p.toLowerCase().includes(filter)));
      const keywordMatch = settings.keywordRegexEnabled
        ? regexFilters.length === 0 || regexFilters.some((keyword) => keyword.test(`${vuln.title} ${vuln.summary}`))
        : keywords.length === 0 || keywords.some((keyword) => haystack.includes(keyword));

      return keywordMatch && productMatch;
    });
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
