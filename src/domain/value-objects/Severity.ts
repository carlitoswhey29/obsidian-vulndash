import type { NormalizedSeverity } from '../sbom/types';

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export const severityOrder: Record<Severity, number> = {
  NONE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

export const normalizedSeverityOrder: Record<NormalizedSeverity, number> = {
  informational: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5
};

export const getSeverityRank = (severity: NormalizedSeverity | undefined): number =>
  severity ? normalizedSeverityOrder[severity] : 0;

export const getHighestSeverity = (
  severities: Iterable<NormalizedSeverity | undefined>
): NormalizedSeverity | undefined => {
  let highest: NormalizedSeverity | undefined;

  for (const severity of severities) {
    if (getSeverityRank(severity) > getSeverityRank(highest)) {
      highest = severity;
    }
  }

  return highest;
};
