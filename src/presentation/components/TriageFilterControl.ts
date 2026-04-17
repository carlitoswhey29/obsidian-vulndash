import type { TriageFilterMode } from '../../application/triage/FilterByTriageState';
import { TRIAGE_STATES, formatTriageStateLabel } from '../../domain/triage/TriageState';

const FILTER_OPTIONS: ReadonlyArray<{
  label: string;
  value: TriageFilterMode;
}> = [
  { label: 'All triage states', value: 'all' },
  { label: 'Active only', value: 'active-only' },
  { label: 'Hide mitigated', value: 'hide-mitigated' },
  ...TRIAGE_STATES.map((state) => ({
    label: formatTriageStateLabel(state),
    value: state
  }))
];

export class TriageFilterControl {
  private rootEl: HTMLDivElement | null = null;
  private selectEl: HTMLSelectElement | null = null;

  public constructor(
    private readonly callbacks: {
      onChange: (value: TriageFilterMode) => void;
    }
  ) {}

  public mount(containerEl: HTMLElement, value: TriageFilterMode): void {
    if (this.rootEl) {
      this.setValue(value);
      return;
    }

    this.rootEl = containerEl.createDiv({ cls: 'vulndash-triage-filter' });
    this.rootEl.createEl('label', { text: 'Triage view' });
    this.selectEl = this.rootEl.createEl('select', { cls: 'vulndash-triage-filter-select' });

    for (const option of FILTER_OPTIONS) {
      const optionEl = this.selectEl.createEl('option', { text: option.label });
      optionEl.value = option.value;
    }

    this.selectEl.addEventListener('change', () => {
      if (!this.selectEl) {
        return;
      }
      this.callbacks.onChange(this.selectEl.value as TriageFilterMode);
    });

    this.setValue(value);
  }

  public setValue(value: TriageFilterMode): void {
    if (this.selectEl && this.selectEl.value !== value) {
      this.selectEl.value = value;
    }
  }
}
