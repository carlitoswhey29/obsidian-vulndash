import type { Vulnerability, VulnerabilityMetadata } from '../entities/Vulnerability';

export interface TriageCorrelationInput {
  readonly source: string;
  readonly vulnerabilityId: string;
  readonly metadata?: VulnerabilityMetadata;
}

const normalizeSegment = (value: string): string =>
  value.trim().toLowerCase();

const normalizeRequiredSegment = (value: string, fieldName: string): string => {
  const normalized = normalizeSegment(value);
  if (normalized.length === 0) {
    throw new Error(`Triage correlation requires a non-empty ${fieldName}.`);
  }

  return normalized;
};

export const resolveTriageIdentity = (input: TriageCorrelationInput): string => {
  const directId = normalizeSegment(input.vulnerabilityId);
  if (directId.length > 0) {
    return directId;
  }

  const fallbacks = [
    input.metadata?.cveId,
    input.metadata?.ghsaId,
    ...(input.metadata?.identifiers ?? []),
    ...(input.metadata?.aliases ?? [])
  ].map((value) => typeof value === 'string' ? normalizeSegment(value) : '')
    .filter((value) => value.length > 0);

  const fallbackIdentity = fallbacks[0];
  if (!fallbackIdentity) {
    throw new Error('Triage correlation requires a vulnerability identity.');
  }

  return fallbackIdentity;
};

export const buildTriageCorrelationKey = (input: TriageCorrelationInput): string =>
  `${normalizeRequiredSegment(input.source, 'source')}::${resolveTriageIdentity(input)}`;

export const buildTriageCorrelationKeyForVulnerability = (
  vulnerability: Pick<Vulnerability, 'id' | 'metadata' | 'source'>
): string =>
  buildTriageCorrelationKey({
    source: vulnerability.source,
    vulnerabilityId: vulnerability.id,
    ...(vulnerability.metadata ? { metadata: vulnerability.metadata } : {})
  });
