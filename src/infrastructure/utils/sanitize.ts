/**
 * Normalizes whitespace and removes standard control characters.
 * Useful for data sanitization before database storage.
 * * WARNING: This does not prevent XSS. Use `escapeHtml` before DOM insertion.
 */
export const sanitizeText = (value: string): string =>
  value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001F\u007F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

/**
 * Sanitizes markdown text while preserving line breaks used by markdown formatting.
 */
export const sanitizeMarkdown = (value: string): string =>
  value
    .replace(/\r\n/g, '\n')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
    .trim();

/**
 * Escapes HTML entities to prevent Cross-Site Scripting (XSS).
 */
export const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');


export const sanitizeUrl = (url: string): string => {
  try {
    const parsed = new URL(url);

    // Enforce strict protocol allowlist
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return '';
    }

    return parsed.toString();
  } catch {
    // Catches malformed URLs and returns a safe fallback
    return '';
  }
};
