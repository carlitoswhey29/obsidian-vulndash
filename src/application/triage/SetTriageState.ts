import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { buildTriageCorrelationKeyForVulnerability } from '../../domain/triage/TriageCorrelation';
import { TriageRecord } from '../../domain/triage/TriageRecord';
import type { TriageRepository } from '../../domain/triage/TriageRepository';
import type { TriageState } from '../../domain/triage/TriageState';

export interface SetTriageStateInput {
  readonly vulnerability: Pick<Vulnerability, 'id' | 'metadata' | 'source'>;
  readonly state: TriageState;
  readonly reason?: string;
  readonly ticketRef?: string;
  readonly updatedAt?: string;
  readonly updatedBy?: string;
}

export class SetTriageState {
  private lastIssuedUpdatedAtMs = 0;

  public constructor(
    private readonly repository: TriageRepository
  ) {}

  public async execute(input: SetTriageStateInput): Promise<TriageRecord> {
    const updatedAt = input.updatedAt ?? this.issueUpdatedAt();
    const record = TriageRecord.create({
      correlationKey: buildTriageCorrelationKeyForVulnerability(input.vulnerability),
      source: input.vulnerability.source,
      state: input.state,
      updatedAt,
      vulnerabilityId: input.vulnerability.id,
      ...(input.reason ? { reason: input.reason } : {}),
      ...(input.ticketRef ? { ticketRef: input.ticketRef } : {}),
      ...(input.updatedBy ? { updatedBy: input.updatedBy } : {})
    });

    return this.repository.save(record);
  }

  private issueUpdatedAt(): string {
    const now = Date.now();
    const nextMs = now > this.lastIssuedUpdatedAtMs ? now : this.lastIssuedUpdatedAtMs + 1;
    this.lastIssuedUpdatedAtMs = nextMs;
    return new Date(nextMs).toISOString();
  }
}
