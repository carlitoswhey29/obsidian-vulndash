const SENSITIVE_HEADER_PATTERN = /authorization|api[-_]?key|token|secret|cookie|session/i;

export const sanitizeHeadersForLogging = (headers: Record<string, string>): Record<string, string> => {
  const sanitized: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    sanitized[key] = SENSITIVE_HEADER_PATTERN.test(key) ? '***REDACTED***' : value;
  }

  return sanitized;
};
