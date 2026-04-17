import { TRIAGE_STATES, formatTriageStateLabel, type TriageState } from '../../domain/triage/TriageState';

const buildStateClassName = (state: TriageState): string =>
  `vulndash-triage-state-${state}`;

const clearTriageStateClasses = (element: HTMLElement): void => {
  for (const state of TRIAGE_STATES) {
    element.classList.remove(buildStateClassName(state));
  }
};

export const applyTriageStatePillAppearance = (element: HTMLElement, state: TriageState): void => {
  element.classList.add('vulndash-triage-pill');
  clearTriageStateClasses(element);
  element.classList.add(buildStateClassName(state));
  element.dataset.triageState = state;
};

export const updateTriageStateSelect = (
  selectEl: HTMLSelectElement,
  state: TriageState,
  disabled: boolean
): void => {
  if (selectEl.value !== state) {
    selectEl.value = state;
  }
  selectEl.disabled = disabled;
  selectEl.title = disabled
    ? `${formatTriageStateLabel(state)} (saving)`
    : `Triage state: ${formatTriageStateLabel(state)}`;
  applyTriageStatePillAppearance(selectEl, state);
  selectEl.classList.toggle('is-pending', disabled);
};

export const createTriageStateSelect = (
  documentRef: Document,
  options: {
    disabled: boolean;
    onChange: (state: TriageState) => void;
    state: TriageState;
  }
): HTMLSelectElement => {
  const selectEl = documentRef.createElement('select');
  selectEl.className = 'vulndash-triage-select';

  for (const state of TRIAGE_STATES) {
    const option = documentRef.createElement('option');
    option.value = state;
    option.textContent = formatTriageStateLabel(state);
    selectEl.append(option);
  }

  for (const eventName of ['click', 'mousedown']) {
    selectEl.addEventListener(eventName, (event) => {
      event.stopPropagation();
    });
  }
  selectEl.addEventListener('change', (event) => {
    event.stopPropagation();
    options.onChange(selectEl.value as TriageState);
  });

  updateTriageStateSelect(selectEl, options.state, options.disabled);
  return selectEl;
};
