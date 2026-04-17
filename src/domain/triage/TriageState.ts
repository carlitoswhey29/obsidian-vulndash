export const TRIAGE_STATES = [
  'active',
  'investigating',
  'accepted_risk',
  'mitigated',
  'false_positive',
  'suppressed'
] as const;

export type TriageState = (typeof TRIAGE_STATES)[number];

export const DEFAULT_TRIAGE_STATE: TriageState = 'active';

export const OPEN_TRIAGE_STATES: readonly TriageState[] = ['active', 'investigating', 'accepted_risk'];
export const CLOSED_TRIAGE_STATES: readonly TriageState[] = ['mitigated', 'false_positive', 'suppressed'];

const TRIAGE_STATE_SET = new Set<string>(TRIAGE_STATES);

const TRIAGE_STATE_LABELS: Record<TriageState, string> = {
  active: 'Active',
  investigating: 'Investigating',
  accepted_risk: 'Accepted Risk',
  mitigated: 'Mitigated',
  false_positive: 'False Positive',
  suppressed: 'Suppressed'
};

const normalizeStateValue = (value: string): string =>
  value.trim().toLowerCase().replace(/[\s-]+/g, '_');

export const isTriageState = (value: unknown): value is TriageState =>
  typeof value === 'string' && TRIAGE_STATE_SET.has(normalizeStateValue(value));

export const parseTriageState = (
  value: unknown,
  fallback: TriageState = DEFAULT_TRIAGE_STATE
): TriageState => {
  if (typeof value !== 'string') {
    return fallback;
  }

  const normalized = normalizeStateValue(value);
  return TRIAGE_STATE_SET.has(normalized) ? normalized as TriageState : fallback;
};

export const formatTriageStateLabel = (state: TriageState): string =>
  TRIAGE_STATE_LABELS[state];

export const isClosedTriageState = (state: TriageState): boolean =>
  CLOSED_TRIAGE_STATES.includes(state);

export const isOpenTriageState = (state: TriageState): boolean =>
  OPEN_TRIAGE_STATES.includes(state);
