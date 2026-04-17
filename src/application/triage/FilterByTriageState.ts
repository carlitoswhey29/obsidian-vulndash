import { DEFAULT_TRIAGE_STATE, isOpenTriageState, isTriageState, parseTriageState, type TriageState } from '../../domain/triage/TriageState';

export type TriageFilterMode = 'all' | 'active-only' | 'hide-mitigated' | TriageState;

export interface TriageFilterable {
  readonly triageState: TriageState;
}

export const normalizeTriageFilterMode = (value: unknown): TriageFilterMode => {
  if (value === 'all' || value === 'active-only' || value === 'hide-mitigated') {
    return value;
  }

  if (isTriageState(value)) {
    return parseTriageState(value);
  }

  return 'all';
};

export class FilterByTriageState {
  public execute<T extends TriageFilterable>(
    items: readonly T[],
    mode: TriageFilterMode
  ): T[] {
    if (mode === 'all') {
      return [...items];
    }

    return items.filter((item) => this.matches(item.triageState, mode));
  }

  public matches(state: TriageState, mode: TriageFilterMode): boolean {
    switch (mode) {
      case 'all':
        return true;
      case 'active-only':
        return isOpenTriageState(state);
      case 'hide-mitigated':
        return state !== 'mitigated';
      default:
        return state === mode;
    }
  }

  public resolve(state: TriageState | null | undefined): TriageState {
    return state ?? DEFAULT_TRIAGE_STATE;
  }
}
