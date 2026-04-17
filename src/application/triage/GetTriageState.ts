import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { TriageRecord } from '../../domain/triage/TriageRecord';
import type { TriageRepository } from '../../domain/triage/TriageRepository';
import { buildTriageCorrelationKey, buildTriageCorrelationKeyForVulnerability, type TriageCorrelationInput } from '../../domain/triage/TriageCorrelation';

export class GetTriageState {
  public constructor(
    private readonly repository: TriageRepository
  ) {}

  public async execute(
    input: Pick<Vulnerability, 'id' | 'metadata' | 'source'> | TriageCorrelationInput
  ): Promise<TriageRecord | null> {
    const correlationKey = 'id' in input
      ? buildTriageCorrelationKeyForVulnerability(input)
      : buildTriageCorrelationKey(input);

    return this.repository.getByCorrelationKey(correlationKey);
  }

  public async executeBulk(
    vulnerabilities: readonly Pick<Vulnerability, 'id' | 'metadata' | 'source'>[]
  ): Promise<ReadonlyMap<string, TriageRecord>> {
    const correlationKeys = Array.from(new Set(vulnerabilities.map((vulnerability) =>
      buildTriageCorrelationKeyForVulnerability(vulnerability)
    )));

    return this.repository.getByCorrelationKeys(correlationKeys);
  }
}
