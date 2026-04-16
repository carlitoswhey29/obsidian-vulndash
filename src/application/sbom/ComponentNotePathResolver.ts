import { normalizePath } from 'obsidian';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import { ComponentIdentityService } from './ComponentIdentityService';

export interface ComponentNoteLookupInput {
  cpe?: string;
  name: string;
  purl?: string;
  version?: string;
}

export interface ComponentNoteCandidate {
  basename: string;
  path: string;
  frontmatter?: Record<string, unknown>;
}

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const getTrimmedString = (value: unknown): string => typeof value === 'string' ? value.trim() : '';

const getStringList = (value: unknown): string[] => {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }

  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((entry) => getTrimmedString(entry))
    .filter((entry) => entry.length > 0);
};

const comparePaths = (left: string, right: string): number =>
  left.localeCompare(right);

interface ComponentNoteReference {
  normalizedBaseName: string;
  normalizedNames: string[];
  nameVersionKey?: string | null;
  path: string;
  semanticKeys: string[];
}

export class ComponentNotePathResolver {
  private readonly identityService = new ComponentIdentityService();
  private readonly nameNormalizer: ProductNameNormalizer;
  private readonly pathsByBaseName = new Map<string, string[]>();
  private readonly pathsByName = new Map<string, string[]>();
  private readonly pathsByNameVersion = new Map<string, string[]>();
  private readonly pathsBySemanticKey = new Map<string, string[]>();

  public constructor(
    candidates: readonly ComponentNoteCandidate[],
    nameNormalizer = new ProductNameNormalizer()
  ) {
    this.nameNormalizer = nameNormalizer;

    for (const candidate of candidates) {
      const reference = this.toReference(candidate);
      this.addValue(this.pathsByBaseName, reference.normalizedBaseName, reference.path);

      for (const normalizedName of reference.normalizedNames) {
        this.addValue(this.pathsByName, normalizedName, reference.path);
      }

      if (reference.nameVersionKey) {
        this.addValue(this.pathsByNameVersion, reference.nameVersionKey, reference.path);
      }

      for (const semanticKey of reference.semanticKeys) {
        this.addValue(this.pathsBySemanticKey, semanticKey, reference.path);
      }
    }
  }

  public resolve(component: ComponentNoteLookupInput): string | null {
    const purl = getTrimmedString(component.purl);
    if (purl) {
      const resolved = this.getUniqueMatch(this.pathsBySemanticKey.get(`purl:${this.identityService.normalizePurlValue(purl)}`));
      if (resolved) {
        return resolved;
      }
    }

    const cpe = getTrimmedString(component.cpe);
    if (cpe) {
      const resolved = this.getUniqueMatch(this.pathsBySemanticKey.get(`cpe:${this.identityService.normalizeCpeValue(cpe)}`));
      if (resolved) {
        return resolved;
      }
    }

    const version = getTrimmedString(component.version);
    if (version) {
      const nameVersionKey = this.identityService.getNameVersionKeyFromParts(component.name, version);
      if (nameVersionKey) {
        const resolvedFromSemanticKey = this.getUniqueMatch(this.pathsBySemanticKey.get(nameVersionKey));
        if (resolvedFromSemanticKey) {
          return resolvedFromSemanticKey;
        }

        const resolvedFromNameVersion = this.getUniqueMatch(this.pathsByNameVersion.get(nameVersionKey));
        if (resolvedFromNameVersion) {
          return resolvedFromNameVersion;
        }
      }

      const normalizedNameVersion = this.normalizeDisplayName(`${component.name} ${version}`);
      if (normalizedNameVersion) {
        const resolvedFromBaseName = this.getUniqueMatch(this.pathsByBaseName.get(normalizedNameVersion));
        if (resolvedFromBaseName) {
          return resolvedFromBaseName;
        }
      }
    }

    const normalizedName = this.normalizeDisplayName(component.name);
    if (normalizedName) {
      const resolvedFromSemanticName = this.getUniqueMatch(this.pathsByName.get(normalizedName));
      if (resolvedFromSemanticName) {
        return resolvedFromSemanticName;
      }

      const resolvedFromBaseName = this.getUniqueMatch(this.pathsByBaseName.get(normalizedName));
      if (resolvedFromBaseName) {
        return resolvedFromBaseName;
      }
    }

    return null;
  }

  private addValue(map: Map<string, string[]>, key: string, path: string): void {
    if (!key) {
      return;
    }

    const current = map.get(key) ?? [];
    if (!current.includes(path)) {
      current.push(path);
      current.sort(comparePaths);
      map.set(key, current);
    }
  }

  private getUniqueMatch(paths: readonly string[] | undefined): string | null {
    if (!paths || paths.length !== 1) {
      return null;
    }

    return paths[0] ?? null;
  }

  private normalizeDisplayName(value: string): string {
    const normalized = this.nameNormalizer.normalize(value);
    return normalizeToken(normalized || value);
  }

  private toReference(candidate: ComponentNoteCandidate): ComponentNoteReference {
    const frontmatter = candidate.frontmatter ?? {};
    const path = normalizePath(candidate.path);
    const normalizedBaseName = this.normalizeDisplayName(candidate.basename);

    const names = [
      candidate.basename,
      ...getStringList(frontmatter.name),
      ...getStringList(frontmatter.component),
      ...getStringList(frontmatter.package),
      ...getStringList(frontmatter.title)
    ]
      .map((value) => this.normalizeDisplayName(value))
      .filter((value, index, values) => value.length > 0 && values.indexOf(value) === index);

    const version = getTrimmedString(frontmatter.version);
    const nameVersionKey = version && names[0]
      ? this.identityService.getNameVersionKeyFromParts(names[0], version)
      : null;

    const semanticKeys = [
      ...getStringList(frontmatter.component_key),
      ...getStringList(frontmatter.componentKey),
      ...getStringList(frontmatter.id),
      ...getStringList(frontmatter.identifiers),
      ...getStringList(frontmatter.aliases)
    ]
      .map((value) => normalizeToken(value))
      .filter((value) => value.startsWith('purl:') || value.startsWith('cpe:') || value.startsWith('name-version:'));

    for (const purl of getStringList(frontmatter.purl)) {
      semanticKeys.push(`purl:${this.identityService.normalizePurlValue(purl)}`);
    }

    for (const cpe of getStringList(frontmatter.cpe)) {
      semanticKeys.push(`cpe:${this.identityService.normalizeCpeValue(cpe)}`);
    }

    if (nameVersionKey) {
      semanticKeys.push(nameVersionKey);
    }

    return {
      normalizedBaseName,
      normalizedNames: names,
      nameVersionKey,
      path,
      semanticKeys: Array.from(new Set(semanticKeys))
    };
  }
}
