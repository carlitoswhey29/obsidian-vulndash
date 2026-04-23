import type {
  NormalizedComponent,
  NormalizedComponentVulnerabilitySummary,
  NormalizedSbomDocument
} from '../../domain/sbom/types';
import { PurlNormalizer } from '../../domain/services/PurlNormalizer';
import type { ParseSbomJsonOptions } from './index';

interface SpdxDocument {
  SPDXID?: unknown;
  creationInfo?: unknown;
  name?: unknown;
  packages?: unknown;
  spdxVersion?: unknown;
}

interface SpdxPackage {
  SPDXID?: unknown;
  externalRefs?: unknown;
  licenseConcluded?: unknown;
  licenseDeclared?: unknown;
  name?: unknown;
  supplier?: unknown;
  versionInfo?: unknown;
}

interface SpdxExternalRef {
  referenceLocator?: unknown;
  referenceType?: unknown;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

const getTrimmedString = (value: unknown): string | undefined => {
  if (typeof value !== 'string') {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const buildEmptyVulnerabilitySummary = (): NormalizedComponentVulnerabilitySummary => ({
  cweIds: [],
  severities: [],
  vulnerabilityCount: 0,
  vulnerabilityIds: []
});

const getExternalReference = (
  pkg: SpdxPackage,
  matcher: (referenceType: string) => boolean
): string | undefined => {
  if (!Array.isArray(pkg.externalRefs)) {
    return undefined;
  }

  for (const reference of pkg.externalRefs) {
    if (!isRecord(reference)) {
      continue;
    }

    const normalizedReference = reference as SpdxExternalRef;
    const referenceType = getTrimmedString(normalizedReference.referenceType)?.toLowerCase();
    if (!referenceType || !matcher(referenceType)) {
      continue;
    }

    const locator = getTrimmedString(normalizedReference.referenceLocator);
    if (locator) {
      return locator;
    }
  }

  return undefined;
};

export const isSpdxJson = (value: unknown): value is SpdxDocument => {
  if (!isRecord(value)) {
    return false;
  }

  const spdxVersion = getTrimmedString(value.spdxVersion);
  if (spdxVersion?.toUpperCase().startsWith('SPDX-')) {
    return true;
  }

  const spdxId = getTrimmedString(value.SPDXID);
  if (spdxId === 'SPDXRef-DOCUMENT') {
    return true;
  }

  return Array.isArray(value.packages) && isRecord(value.creationInfo);
};

export const parseSpdxJson = (
  document: SpdxDocument,
  options: ParseSbomJsonOptions
): NormalizedSbomDocument => {
  const packages = Array.isArray(document.packages)
    ? document.packages.filter(isRecord) as SpdxPackage[]
    : [];

  const components = packages.map((pkg, index) => {
    const name = getTrimmedString(pkg.name) ?? `Unnamed package ${index + 1}`;
    const version = getTrimmedString(pkg.versionInfo);
    const purl = getExternalReference(pkg, (referenceType) => referenceType.includes('purl'));
    const cpe = getExternalReference(pkg, (referenceType) => referenceType.includes('cpe'));
    const license = getTrimmedString(pkg.licenseDeclared) ?? getTrimmedString(pkg.licenseConcluded);

    const normalized: NormalizedComponent = {
      cweGroups: [],
      id: getTrimmedString(pkg.SPDXID) ?? `${name}@${version ?? 'unknown'}#${index}`,
      name,
      vulnerabilitySummary: buildEmptyVulnerabilitySummary(),
      vulnerabilities: [],
      vulnerabilityCount: 0
    };

    if (version) {
      normalized.version = version;
    }

    const supplier = getTrimmedString(pkg.supplier);
    if (supplier) {
      normalized.supplier = supplier;
    }
    if (license) {
      normalized.license = license;
    }
    if (purl) {
      normalized.purl = PurlNormalizer.normalize(purl)!;
    }
    if (cpe) {
      normalized.cpe = cpe;
    }
    if (options.resolveNotePath) {
      const noteInput: {
        cpe?: string;
        name: string;
        purl?: string;
        version?: string;
      } = { name };
      if (cpe) {
        noteInput.cpe = cpe;
      }
      if (purl) {
        noteInput.purl = purl;
      }
      if (version) {
        noteInput.version = version;
      }

      const notePath = options.resolveNotePath(noteInput);
      if (notePath !== undefined) {
        normalized.notePath = notePath;
      }
    }

    return normalized;
  });

  return {
    components,
    format: 'spdx',
    name: getTrimmedString(document.name) ?? options.source.basename,
    sourcePath: options.source.path
  };
};
