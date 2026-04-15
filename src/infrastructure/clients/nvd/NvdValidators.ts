import type { NvdDateRange } from './NvdTypes';

export const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
export const NVD_RESULTS_PER_PAGE = 100;
export const NVD_MAX_START_INDEX = 1_000_000;

const ISO_8601_UTC_REGEX =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;

export function validateIsoUtcDate(value: string, fieldName: string): string {
  const trimmed = value.trim();

  if (trimmed.length === 0) {
    throw new Error(`${fieldName} must not be empty.`);
  }

  if (!ISO_8601_UTC_REGEX.test(trimmed)) {
    throw new Error(
      `${fieldName} must be a valid ISO-8601 UTC timestamp like 2026-04-15T00:00:00.000Z.`
    );
  }

  const timestamp = Date.parse(trimmed);
  if (Number.isNaN(timestamp)) {
    throw new Error(`${fieldName} is not a valid date.`);
  }

  return trimmed;
}

export function validateDateRange(
  since: string | undefined,
  until: string | undefined
): NvdDateRange {
  const safeSince = since ? validateIsoUtcDate(since, 'lastModStartDate') : undefined;
  const safeUntil = until ? validateIsoUtcDate(until, 'lastModEndDate') : undefined;

  if (safeSince && safeUntil && Date.parse(safeSince) > Date.parse(safeUntil)) {
    throw new Error('lastModStartDate must be less than or equal to lastModEndDate.');
  }

  return {
    ...(safeSince ? { since: safeSince } : {}),
    ...(safeUntil ? { until: safeUntil } : {})
  };
}

export function validateStartIndex(startIndex: number): number {
  if (!Number.isInteger(startIndex)) {
    throw new Error('startIndex must be an integer.');
  }

  if (startIndex < 0) {
    throw new Error('startIndex must be greater than or equal to 0.');
  }

  if (startIndex > NVD_MAX_START_INDEX) {
    throw new Error(`startIndex exceeds maximum allowed value of ${NVD_MAX_START_INDEX}.`);
  }

  return startIndex;
}

export function validateApiKey(apiKey: string): string {
  const trimmed = apiKey.trim();

  if (trimmed.length === 0) {
    throw new Error('apiKey must not be empty.');
  }

  if (trimmed.length > 256) {
    throw new Error('apiKey is too long.');
  }

  if (/[\r\n]/.test(trimmed)) {
    throw new Error('apiKey contains invalid control characters.');
  }

  return trimmed;
}
