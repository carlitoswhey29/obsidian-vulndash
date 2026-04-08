const REDACTED = '[REDACTED]';
const SENSITIVE_KEY_PATTERN = /(?:^|[-_])(?:token|apikey|api-key|authorization|auth|secret|bearer|x-api-key)(?:$|[-_])/i;
const SENSITIVE_STRING_PATTERNS: RegExp[] = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g
];

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object'
  && value !== null
  && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);

export const redactSensitiveString = (value: string): string => {
  let redacted = value
    .replace(/([?&](?:apiKey|api_key|token|auth|authorization|bearer|secret|x-api-key)=)[^&\s]+/gi, `$1${REDACTED}`)
    .replace(
      /(^|[\s,{])((?:auth|authorization)\s*[:=]\s*)(?:Bearer\s+[A-Za-z0-9._~+/=-]+|[^\s,;}]+)/gi,
      `$1$2${REDACTED}`
    )
    .replace(
      /(^|[\s,{])((?:apiKey|api_key|token|bearer|secret|x-api-key)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi,
      `$1$2${REDACTED}`
    )
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, `Bearer ${REDACTED}`);

  for (const pattern of SENSITIVE_STRING_PATTERNS) {
    redacted = redacted.replace(pattern, REDACTED);
  }

  return redacted;
};

export const redactSensitive = (value: unknown, seen = new WeakSet<object>()): unknown => {
  if (typeof value === 'string') {
    return redactSensitiveString(value);
  }

  if (Array.isArray(value)) {
    if (seen.has(value)) {
      return '[Circular]';
    }
    seen.add(value);
    return value.map((item) => redactSensitive(item, seen));
  }

  if (!isPlainObject(value)) {
    return value;
  }

  if (seen.has(value)) {
    return '[Circular]';
  }
  seen.add(value);

  return Object.fromEntries(
    Object.entries(value).map(([key, nestedValue]) => [
      key,
      SENSITIVE_KEY_PATTERN.test(key) ? REDACTED : redactSensitive(nestedValue, seen)
    ])
  );
};

const log = (level: 'info' | 'warn' | 'error', message: string, payload?: unknown): void => {
  if (payload === undefined) {
    console[level](redactSensitiveString(message));
    return;
  }

  console[level](redactSensitiveString(message), redactSensitive(payload));
};

export const logger = {
  info(message: string, payload?: unknown): void {
    log('info', message, payload);
  },

  warn(message: string, payload?: unknown): void {
    log('warn', message, payload);
  },

  error(message: string, payload?: unknown): void {
    log('error', message, payload);
  }
};
