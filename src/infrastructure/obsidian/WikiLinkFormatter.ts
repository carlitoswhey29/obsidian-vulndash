export interface WikiLinkParts {
  target: string;
  displayName?: string;
}

const normalizeWikiLinkValue = (value: string): string =>
  value
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .replace(/\n+/g, ' ')
    .replace(/[[\]#^|]/g, '')
    .replace(/\s+/g, ' ')
    .trim();

const normalizeNotePath = (value: string): string =>
  value
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^\.?\//, '')
    .replace(/\.md$/i, '');

export class WikiLinkFormatter {
  public format(notePath: string, displayName?: string): string {
    const normalizedPath = this.normalizeTarget(notePath);
    const normalizedDisplayName = this.normalizeDisplayName(displayName ?? '');

    if (!normalizedPath) {
      return normalizedDisplayName ? `[[${normalizedDisplayName}]]` : '';
    }

    const defaultDisplayName = normalizedPath.split('/').at(-1) ?? normalizedPath;

    if (!normalizedDisplayName || normalizedDisplayName === defaultDisplayName) {
      return `[[${normalizedPath}]]`;
    }

    return `[[${normalizedPath}|${normalizedDisplayName}]]`;
  }

  public formatParts(parts: WikiLinkParts): string {
    return this.format(parts.target, parts.displayName);
  }

  public normalizeTarget(notePath: string): string {
    return normalizeWikiLinkValue(normalizeNotePath(notePath));
  }

  public normalizeDisplayName(displayName: string): string {
    return normalizeWikiLinkValue(displayName);
  }
}
