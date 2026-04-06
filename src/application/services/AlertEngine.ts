import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { severityOrder } from '../../domain/entities/Severity';
import type { VulnDashSettings } from './types';

export class AlertEngine {
  public filter(vulnerabilities: Vulnerability[], settings: VulnDashSettings): Vulnerability[] {
    const keywords = settings.keywordFilters.map((v) => v.toLowerCase());
    const products = settings.productFilters.map((v) => v.toLowerCase());
    const minSeverityRank = severityOrder[settings.minSeverity];

    return vulnerabilities.filter((vuln) => {
      if (vuln.cvssScore < settings.minCvssScore) return false;
      if (severityOrder[vuln.severity] < minSeverityRank) return false;

      const haystack = `${vuln.title} ${vuln.summary}`.toLowerCase();
      const productMatch = products.length === 0
        || vuln.affectedProducts.some((p) => products.some((filter) => p.toLowerCase().includes(filter)));
      const keywordMatch = keywords.length === 0 || keywords.some((keyword) => haystack.includes(keyword));

      return keywordMatch && productMatch;
    });
  }
}
