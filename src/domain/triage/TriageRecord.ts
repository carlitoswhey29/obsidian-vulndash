import { parseTriageState, type TriageState } from './TriageState';

export interface TriageRecordProps {
  readonly correlationKey: string;
  readonly vulnerabilityId: string;
  readonly source: string;
  readonly state: TriageState;
  readonly updatedAt: string;
  readonly reason?: string;
  readonly ticketRef?: string;
  readonly updatedBy?: string;
}

const normalizeRequiredString = (value: string, fieldName: string): string => {
  const normalized = value.trim();
  if (normalized.length === 0) {
    throw new Error(`TriageRecord requires a non-empty ${fieldName}.`);
  }

  return normalized;
};

const normalizeOptionalString = (value: string | undefined): string | undefined => {
  const normalized = value?.trim();
  return normalized && normalized.length > 0 ? normalized : undefined;
};

const normalizeUpdatedAt = (value: string): string => {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error('TriageRecord requires a valid updatedAt timestamp.');
  }

  return new Date(timestamp).toISOString();
};

export class TriageRecord {
  public readonly correlationKey: string;
  public readonly vulnerabilityId: string;
  public readonly source: string;
  public readonly state: TriageState;
  public readonly updatedAt: string;
  public readonly reason: string | undefined;
  public readonly ticketRef: string | undefined;
  public readonly updatedBy: string | undefined;

  private constructor(props: {
    correlationKey: string;
    reason: string | undefined;
    source: string;
    state: TriageState;
    ticketRef: string | undefined;
    updatedAt: string;
    updatedBy: string | undefined;
    vulnerabilityId: string;
  }) {
    this.correlationKey = props.correlationKey;
    this.vulnerabilityId = props.vulnerabilityId;
    this.source = props.source;
    this.state = props.state;
    this.updatedAt = props.updatedAt;
    this.reason = props.reason;
    this.ticketRef = props.ticketRef;
    this.updatedBy = props.updatedBy;
    Object.freeze(this);
  }

  public static create(props: Omit<TriageRecordProps, 'state'> & { state: TriageState | string }): TriageRecord {
    return new TriageRecord({
      correlationKey: normalizeRequiredString(props.correlationKey, 'correlationKey'),
      reason: normalizeOptionalString(props.reason),
      source: normalizeRequiredString(props.source, 'source'),
      state: parseTriageState(props.state),
      ticketRef: normalizeOptionalString(props.ticketRef),
      updatedAt: normalizeUpdatedAt(props.updatedAt),
      updatedBy: normalizeOptionalString(props.updatedBy),
      vulnerabilityId: normalizeRequiredString(props.vulnerabilityId, 'vulnerabilityId')
    });
  }

  public toJSON(): TriageRecordProps {
    return {
      correlationKey: this.correlationKey,
      vulnerabilityId: this.vulnerabilityId,
      source: this.source,
      state: this.state,
      updatedAt: this.updatedAt,
      ...(this.reason ? { reason: this.reason } : {}),
      ...(this.ticketRef ? { ticketRef: this.ticketRef } : {}),
      ...(this.updatedBy ? { updatedBy: this.updatedBy } : {})
    };
  }
}
