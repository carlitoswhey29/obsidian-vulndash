export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const redacted: Record<string, string> = {};

  for (const [key, value] of Object.entries(headers)) {
    redacted[key] = key.toLowerCase().includes('key') || key.toLowerCase().includes('auth')
      ? '***REDACTED***'
      : value;
  }

  return redacted;
}
