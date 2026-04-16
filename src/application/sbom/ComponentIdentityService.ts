import type { NormalizedComponent } from '../../domain/sbom/types';

const UNNAMED_COMPONENT_PATTERN = /^unnamed (component|package)( \d+)?$/i;

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const normalizePurl = (value: string): string =>
  normalizeToken(value);

const normalizeCpe = (value: string): string =>
  normalizeToken(value);

const normalizeComponentName = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }

  const normalized = normalizeToken(value);
  if (!normalized || UNNAMED_COMPONENT_PATTERN.test(normalized)) {
    return undefined;
  }

  return normalized;
};

const normalizeVersion = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }

  const normalized = normalizeToken(value);
  return normalized || undefined;
};

export class ComponentIdentityService {
  public getCanonicalKey(component: NormalizedComponent): string {
    const purl = component.purl?.trim();
    if (purl) {
      return `purl:${normalizePurl(purl)}`;
    }

    const cpe = component.cpe?.trim();
    if (cpe) {
      return `cpe:${normalizeCpe(cpe)}`;
    }

    const name = normalizeComponentName(component.name);
    const version = normalizeVersion(component.version);

    if (name && version) {
      return `name-version:${name}@${version}`;
    }

    if (name) {
      return `name:${name}`;
    }

    const fallbackParts = [
      component.supplier,
      component.license,
      component.notePath ?? undefined
    ]
      .map((value) => value?.trim())
      .filter((value): value is string => Boolean(value))
      .map((value) => normalizeToken(value));

    if (fallbackParts.length > 0) {
      return `unresolved:${fallbackParts.join('|')}`;
    }

    return 'unresolved:component';
  }
}
