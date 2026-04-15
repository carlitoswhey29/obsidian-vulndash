const REDACTED_VALUE = '[REDACTED]';
const SENSITIVE_HEADERS = new Set([
  'authorization',
  'proxy-authorization',
  'apikey',
  'api-key',
  'x-api-key',
  'cookie',
  'set-cookie'
]);

export const sanitizeHeadersForLogs = (headers: Record<string, string>): Record<string, string> => {
  const sanitized: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    sanitized[key] = SENSITIVE_HEADERS.has(key.toLowerCase()) ? REDACTED_VALUE : value;
  }

  return sanitized;
};
