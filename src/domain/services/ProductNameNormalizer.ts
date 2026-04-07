export class ProductNameNormalizer {
  public normalize(rawName: string): string {
    const trimmed = rawName.trim();
    if (!trimmed) {
      return '';
    }

    if (trimmed.startsWith('cpe:2.3:')) {
      return this.normalizeCpe(trimmed);
    }

    return this.normalizeGeneric(trimmed);
  }

  private normalizeCpe(cpe: string): string {
    const parts = cpe.split(':');
    const vendor = this.cleanCpeToken(parts[3] ?? '');
    const product = this.cleanCpeToken(parts[4] ?? '');
    const version = this.cleanCpeToken(parts[5] ?? '');

    const base = [vendor, product].filter(Boolean).join(' ');
    const namedBase = this.toDisplayName(base);
    if (!namedBase) {
      return this.normalizeGeneric(cpe);
    }

    if (!version || version === '*' || version === '-') {
      return namedBase;
    }

    return `${namedBase} ${version}`;
  }

  private cleanCpeToken(token: string): string {
    if (!token || token === '*' || token === '-') {
      return '';
    }

    return token
      .replace(/\\([\\:*?!])/g, '$1')
      .replace(/_/g, ' ')
      .trim();
  }

  private normalizeGeneric(value: string): string {
    const collapsed = value
      .replace(/[@/]/g, ' ')
      .replace(/[_-]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    return this.toDisplayName(collapsed);
  }

  private toDisplayName(value: string): string {
    return value
      .split(' ')
      .filter(Boolean)
      .map((part) => {
        if (/^\d+(\.\d+)*$/.test(part)) {
          return part;
        }
        return part.charAt(0).toUpperCase() + part.slice(1);
      })
      .join(' ');
  }
}
