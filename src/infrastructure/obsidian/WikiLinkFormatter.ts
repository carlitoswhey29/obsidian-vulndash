const normalizeWikiLinkValue = (value: string): string =>
  value.replace(/[\]|]/g, '').trim();

const normalizeNotePath = (value: string): string =>
  value
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^\.?\//, '')
    .replace(/\.md$/i, '');

export class WikiLinkFormatter {
  public format(notePath: string, displayName?: string): string {
    const normalizedPath = normalizeWikiLinkValue(normalizeNotePath(notePath));
    const normalizedDisplayName = normalizeWikiLinkValue(displayName ?? '');

    if (!normalizedPath) {
      return normalizedDisplayName ? `[[${normalizedDisplayName}]]` : '[[]]';
    }

    if (!normalizedDisplayName || normalizedDisplayName === normalizedPath.split('/').at(-1)) {
      return `[[${normalizedPath}]]`;
    }

    return `[[${normalizedPath}|${normalizedDisplayName}]]`;
  }
}
