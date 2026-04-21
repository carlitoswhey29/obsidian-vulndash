export interface ResolvedLinkTarget {
  target: string;
  displayName?: string;
}

export interface ResolvedComponentLinkInput {
  name: string;
  version?: string;
  displayName?: string;
  includeVersionInTarget?: boolean;
}

export class LinkResolver {
  public note(target: string, displayName?: string): ResolvedLinkTarget {
    const normalizedTarget = this.normalizeRequiredValue(target);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);

    return {
      target: normalizedTarget,
      ...(normalizedDisplayName ? { displayName: normalizedDisplayName } : {})
    };
  }

  public vulnerability(cveId: string, displayName?: string): ResolvedLinkTarget {
    const normalizedTarget = this.normalizeRequiredValue(cveId);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);

    return {
      target: normalizedTarget,
      ...(normalizedDisplayName ? { displayName: normalizedDisplayName } : {})
    };
  }

  public advisory(ghsaId: string, displayName?: string): ResolvedLinkTarget {
    const normalizedTarget = this.normalizeRequiredValue(ghsaId);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);

    return {
      target: normalizedTarget,
      ...(normalizedDisplayName ? { displayName: normalizedDisplayName } : {})
    };
  }

  public project(projectName: string, displayName?: string): ResolvedLinkTarget {
    const normalizedTarget = this.normalizeRequiredValue(projectName);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);

    return {
      target: normalizedTarget,
      ...(normalizedDisplayName ? { displayName: normalizedDisplayName } : {})
    };
  }

  public component(input: ResolvedComponentLinkInput): ResolvedLinkTarget {
    const normalizedName = this.normalizeRequiredValue(input.name);
    const normalizedVersion = this.normalizeOptionalValue(input.version);
    const normalizedDisplayName = this.normalizeOptionalValue(input.displayName);
    const includeVersionInTarget = input.includeVersionInTarget ?? true;

    const target =
      includeVersionInTarget && normalizedVersion
        ? `${normalizedName} ${normalizedVersion}`
        : normalizedName;

    return {
      target,
      ...(normalizedDisplayName ? { displayName: normalizedDisplayName } : {})
    };
  }

  public packageVersion(
    packageName: string,
    version?: string,
    displayName?: string
  ): ResolvedLinkTarget {
    const normalizedPackageName = this.normalizeRequiredValue(packageName);
    const normalizedVersion = this.normalizeOptionalValue(version);
    const normalizedDisplayName = this.normalizeOptionalValue(displayName);

    const target = normalizedVersion
      ? `${normalizedPackageName}@${normalizedVersion}`
      : normalizedPackageName;

    return {
      target,
      ...(normalizedDisplayName ? { displayName: normalizedDisplayName } : {})
    };
  }

  private normalizeRequiredValue(value: string): string {
    return this.normalizeValue(value);
  }

  private normalizeValue(value: string): string {
    return value
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/\n+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim();
  }

  private normalizeOptionalValue(value?: string): string | undefined {
    if (typeof value !== 'string') {
      return undefined;
    }

    const normalized = this.normalizeValue(value);
    return normalized.length > 0 ? normalized : undefined;
  }
}
