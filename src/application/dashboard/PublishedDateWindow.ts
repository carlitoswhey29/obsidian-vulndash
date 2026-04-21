import type { Vulnerability } from '../../domain/entities/Vulnerability';

const DAY_IN_MS = 24 * 60 * 60 * 1000;
const CALENDAR_DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;

export type DashboardDateRangePreset = 'past_day' | 'past_3_days' | 'past_7_days' | 'custom';

export interface DashboardDateRangeSelection {
  readonly preset: DashboardDateRangePreset;
  readonly customFrom?: string;
  readonly customTo?: string;
}

export interface ResolvedPublishedDateWindow {
  readonly from: string;
  readonly to: string;
}

export interface DashboardDateRangeResolution {
  readonly isValid: boolean;
  readonly validationMessage?: string;
  readonly window?: ResolvedPublishedDateWindow;
}

export const DEFAULT_DASHBOARD_DATE_RANGE: DashboardDateRangeSelection = {
  preset: 'past_day'
};

const buildValidationResult = (
  isValid: boolean,
  window?: ResolvedPublishedDateWindow,
  validationMessage?: string
): DashboardDateRangeResolution => ({
  isValid,
  ...(validationMessage ? { validationMessage } : {}),
  ...(window ? { window } : {})
});

const toLocalDayBoundary = (value: string, boundary: 'start' | 'end'): Date | null => {
  const trimmed = value.trim();
  if (!CALENDAR_DATE_PATTERN.test(trimmed)) {
    return null;
  }

  const [yearText, monthText, dayText] = trimmed.split('-');
  const year = Number.parseInt(yearText ?? '', 10);
  const monthIndex = Number.parseInt(monthText ?? '', 10) - 1;
  const day = Number.parseInt(dayText ?? '', 10);
  if (!Number.isInteger(year) || !Number.isInteger(monthIndex) || !Number.isInteger(day)) {
    return null;
  }

  const candidate = boundary === 'start'
    ? new Date(year, monthIndex, day, 0, 0, 0, 0)
    : new Date(year, monthIndex, day, 23, 59, 59, 999);
  if (
    candidate.getFullYear() !== year
    || candidate.getMonth() !== monthIndex
    || candidate.getDate() !== day
  ) {
    return null;
  }

  return candidate;
};

const createPresetWindow = (
  now: Date,
  lookbackMs: number
): ResolvedPublishedDateWindow => ({
  from: new Date(now.getTime() - lookbackMs).toISOString(),
  to: now.toISOString()
});

export const cloneDashboardDateRangeSelection = (
  selection: DashboardDateRangeSelection
): DashboardDateRangeSelection => ({
  preset: selection.preset,
  ...(selection.customFrom ? { customFrom: selection.customFrom } : {}),
  ...(selection.customTo ? { customTo: selection.customTo } : {})
});

export const resolveDashboardDateRangeSelection = (
  selection: DashboardDateRangeSelection,
  now = new Date()
): DashboardDateRangeResolution => {
  switch (selection.preset) {
    case 'past_3_days':
      return buildValidationResult(true, createPresetWindow(now, 3 * DAY_IN_MS));
    case 'past_7_days':
      return buildValidationResult(true, createPresetWindow(now, 7 * DAY_IN_MS));
    case 'custom': {
      const customFrom = selection.customFrom?.trim() ?? '';
      const customTo = selection.customTo?.trim() ?? '';
      if (!customFrom || !customTo) {
        return buildValidationResult(false, undefined, 'Both From and To dates are required.');
      }

      const start = toLocalDayBoundary(customFrom, 'start');
      const end = toLocalDayBoundary(customTo, 'end');
      if (!start || !end) {
        return buildValidationResult(false, undefined, 'Enter valid calendar dates for the custom range.');
      }

      if (start.getTime() > end.getTime()) {
        return buildValidationResult(false, undefined, 'From date must be on or before the To date.');
      }

      return buildValidationResult(true, {
        from: start.toISOString(),
        to: end.toISOString()
      });
    }
    case 'past_day':
    default:
      return buildValidationResult(true, createPresetWindow(now, DAY_IN_MS));
  }
};

export const filterVulnerabilitiesByPublishedDateWindow = (
  vulnerabilities: readonly Vulnerability[],
  window: ResolvedPublishedDateWindow
): Vulnerability[] => {
  const fromMs = Date.parse(window.from);
  const toMs = Date.parse(window.to);
  if (Number.isNaN(fromMs) || Number.isNaN(toMs)) {
    return [...vulnerabilities];
  }

  return vulnerabilities.filter((vulnerability) => {
    const publishedAtMs = Date.parse(vulnerability.publishedAt);
    return !Number.isNaN(publishedAtMs) && publishedAtMs >= fromMs && publishedAtMs <= toMs;
  });
};
