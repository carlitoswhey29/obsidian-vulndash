import type {
  NormalizedComponent,
  NormalizedCweGroup,
  NormalizedDataviewFields,
  NormalizedSbomDocument,
  NormalizedSeverity,
  NormalizedVulnerability
} from '../../domain/sbom/types';
import type { ParseSbomJsonOptions } from './index';

interface CycloneDxBom {
  bomFormat?: unknown;
  components?: unknown;
  metadata?: unknown;
  specVersion?: unknown;
  vulnerabilities?: unknown;
}

interface CycloneDxMetadata {
  component?: unknown;
}

interface CycloneDxComponent {
  'bom-ref'?: unknown;
  components?: unknown;
  cpe?: unknown;
  licenses?: unknown;
  name?: unknown;
  purl?: unknown;
  supplier?: unknown;
  version?: unknown;
}

interface CycloneDxSupplier {
  name?: unknown;
}

interface CycloneDxLicenseChoice {
  expression?: unknown;
  license?: unknown;
}

interface CycloneDxLicense {
  id?: unknown;
  name?: unknown;
}

interface CycloneDxVulnerability {
  'bom-ref'?: unknown;
  affects?: unknown;
  cwes?: unknown;
  description?: unknown;
  id?: unknown;
  published?: unknown;
  ratings?: unknown;
  source?: unknown;
  updated?: unknown;
}

interface CycloneDxVulnerabilityRating {
  method?: unknown;
  score?: unknown;
  severity?: unknown;
  source?: unknown;
  vector?: unknown;
}

interface CycloneDxSource {
  name?: unknown;
  url?: unknown;
}

interface CycloneDxAffect {
  ref?: unknown;
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

const getFiniteNumber = (value: unknown): number | undefined =>
  typeof value === 'number' && Number.isFinite(value) ? value : undefined;

const normalizeSeverity = (severity: unknown): NormalizedSeverity | undefined => {
  const normalized = getTrimmedString(severity)?.toLowerCase();

  switch (normalized) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    case 'info':
    case 'informational':
      return 'informational';
    default:
      return undefined;
  }
};

const getSeverityRank = (severity: NormalizedSeverity | undefined): number => {
  switch (severity) {
    case 'critical':
      return 5;
    case 'high':
      return 4;
    case 'medium':
      return 3;
    case 'low':
      return 2;
    case 'informational':
      return 1;
    default:
      return 0;
  }
};

const compareVulnerabilities = (
  left: NormalizedVulnerability,
  right: NormalizedVulnerability
): number => {
  const severityDiff = getSeverityRank(right.severity) - getSeverityRank(left.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  const rightScore = right.score ?? -1;
  const leftScore = left.score ?? -1;
  if (rightScore !== leftScore) {
    return rightScore - leftScore;
  }

  return left.id.localeCompare(right.id);
};

const getHighestSeverity = (
  vulnerabilities: readonly NormalizedVulnerability[]
): NormalizedSeverity | undefined => {
  let highest: NormalizedSeverity | undefined;

  for (const vulnerability of vulnerabilities) {
    if (getSeverityRank(vulnerability.severity) > getSeverityRank(highest)) {
      highest = vulnerability.severity;
    }
  }

  return highest;
};

const buildCweGroups = (
  vulnerabilities: readonly NormalizedVulnerability[]
): NormalizedCweGroup[] => {
  const groups = new Map<number, Set<string>>();

  for (const vulnerability of vulnerabilities) {
    for (const cwe of vulnerability.cwes) {
      const current = groups.get(cwe) ?? new Set<string>();
      current.add(vulnerability.id);
      groups.set(cwe, current);
    }
  }

  return Array.from(groups.entries())
    .map(([cwe, vulnerabilityIds]) => ({
      count: vulnerabilityIds.size,
      cwe,
      vulnerabilityIds: Array.from(vulnerabilityIds).sort((left, right) => left.localeCompare(right))
    }))
    .sort((left, right) => left.cwe - right.cwe);
};

const buildDataviewFields = (
  vulnerabilities: readonly NormalizedVulnerability[]
): NormalizedDataviewFields => {
  const cweList = new Set<string>();
  const severities = new Set<NormalizedSeverity>();

  for (const vulnerability of vulnerabilities) {
    for (const cwe of vulnerability.cwes) {
      cweList.add(`CWE-${cwe}`);
    }

    if (vulnerability.severity) {
      severities.add(vulnerability.severity);
    }
  }

  const dataview: NormalizedDataviewFields = {
    cweList: Array.from(cweList).sort((left, right) => left.localeCompare(right)),
    severities: Array.from(severities).sort((left, right) => getSeverityRank(right) - getSeverityRank(left)),
    vulnerabilityCount: vulnerabilities.length,
    vulnerabilityIds: vulnerabilities.map((vulnerability) => vulnerability.id)
  };

  const highestSeverity = getHighestSeverity(vulnerabilities);
  if (highestSeverity) {
    dataview.highestSeverity = highestSeverity;
  }

  return dataview;
};

const buildEmptyDataviewFields = (): NormalizedDataviewFields => ({
  cweList: [],
  severities: [],
  vulnerabilityCount: 0,
  vulnerabilityIds: []
});

const flattenComponents = (bom: CycloneDxBom): CycloneDxComponent[] => {
  const queue: CycloneDxComponent[] = [];
  const metadata = isRecord(bom.metadata) ? (bom.metadata as CycloneDxMetadata) : null;
  if (isRecord(metadata?.component)) {
    queue.push(metadata.component as CycloneDxComponent);
  }

  if (Array.isArray(bom.components)) {
    queue.push(...bom.components.filter(isRecord) as CycloneDxComponent[]);
  }

  const flattened: CycloneDxComponent[] = [];
  while (queue.length > 0) {
    const component = queue.shift();
    if (!component) {
      continue;
    }

    flattened.push(component);
    if (Array.isArray(component.components)) {
      queue.push(...component.components.filter(isRecord) as CycloneDxComponent[]);
    }
  }

  return flattened;
};

const getPrimaryLicense = (component: CycloneDxComponent): string | undefined => {
  if (!Array.isArray(component.licenses)) {
    return undefined;
  }

  for (const entry of component.licenses) {
    if (!isRecord(entry)) {
      continue;
    }

    const licenseChoice = entry as CycloneDxLicenseChoice;
    const expression = getTrimmedString(licenseChoice.expression);
    if (expression) {
      return expression;
    }

    if (!isRecord(licenseChoice.license)) {
      continue;
    }

    const license = licenseChoice.license as CycloneDxLicense;
    const id = getTrimmedString(license.id);
    if (id) {
      return id;
    }

    const name = getTrimmedString(license.name);
    if (name) {
      return name;
    }
  }

  return undefined;
};

const normalizeCycloneDxVulnerability = (
  vulnerability: CycloneDxVulnerability
): NormalizedVulnerability => {
  const firstRating = Array.isArray(vulnerability.ratings)
    ? vulnerability.ratings.find((rating) => isRecord(rating)) as CycloneDxVulnerabilityRating | undefined
    : undefined;
  const vulnerabilitySource = isRecord(vulnerability.source)
    ? (vulnerability.source as CycloneDxSource)
    : undefined;
  const ratingSource = isRecord(firstRating?.source)
    ? (firstRating.source as CycloneDxSource)
    : undefined;

  const normalized: NormalizedVulnerability = {
    cwes: Array.isArray(vulnerability.cwes)
      ? vulnerability.cwes.filter((cwe): cwe is number => typeof cwe === 'number' && Number.isInteger(cwe))
      : [],
    id: getTrimmedString(vulnerability.id)
      ?? getTrimmedString(vulnerability['bom-ref'])
      ?? 'unknown-vulnerability'
  };

  const bomRef = getTrimmedString(vulnerability['bom-ref']);
  if (bomRef) {
    normalized.bomRef = bomRef;
  }

  const sourceName = getTrimmedString(vulnerabilitySource?.name) ?? getTrimmedString(ratingSource?.name);
  if (sourceName) {
    normalized.sourceName = sourceName;
  }

  const sourceUrl = getTrimmedString(vulnerabilitySource?.url) ?? getTrimmedString(ratingSource?.url);
  if (sourceUrl) {
    normalized.sourceUrl = sourceUrl;
  }

  const severity = normalizeSeverity(firstRating?.severity);
  if (severity) {
    normalized.severity = severity;
  }

  const score = getFiniteNumber(firstRating?.score);
  if (score !== undefined) {
    normalized.score = score;
  }

  const method = getTrimmedString(firstRating?.method);
  if (method) {
    normalized.method = method;
  }

  const vector = getTrimmedString(firstRating?.vector);
  if (vector) {
    normalized.vector = vector;
  }

  const description = getTrimmedString(vulnerability.description);
  if (description) {
    normalized.description = description;
  }

  const published = getTrimmedString(vulnerability.published);
  if (published) {
    normalized.published = published;
  }

  const updated = getTrimmedString(vulnerability.updated);
  if (updated) {
    normalized.updated = updated;
  }

  return normalized;
};

const buildVulnerabilityIndex = (
  bom: CycloneDxBom
): Map<string, NormalizedVulnerability[]> => {
  const index = new Map<string, Map<string, NormalizedVulnerability>>();
  const vulnerabilities = Array.isArray(bom.vulnerabilities)
    ? bom.vulnerabilities.filter(isRecord) as CycloneDxVulnerability[]
    : [];

  for (const vulnerability of vulnerabilities) {
    const normalized = normalizeCycloneDxVulnerability(vulnerability);
    const affects = Array.isArray(vulnerability.affects)
      ? vulnerability.affects.filter(isRecord) as CycloneDxAffect[]
      : [];

    for (const affected of affects) {
      const ref = getTrimmedString(affected.ref);
      if (!ref) {
        continue;
      }

      const entries = index.get(ref) ?? new Map<string, NormalizedVulnerability>();
      entries.set(normalized.id, normalized);
      index.set(ref, entries);
    }
  }

  return new Map(Array.from(index.entries()).map(([ref, vulnerabilities]) => ([
    ref,
    Array.from(vulnerabilities.values()).sort(compareVulnerabilities)
  ])));
};

export const isCycloneDxJson = (value: unknown): value is CycloneDxBom => {
  if (!isRecord(value)) {
    return false;
  }

  const bomFormat = getTrimmedString(value.bomFormat)?.toLowerCase();
  if (bomFormat === 'cyclonedx') {
    return true;
  }

  const hasSpecVersion = getTrimmedString(value.specVersion) !== undefined;
  const hasComponents = Array.isArray(value.components);
  const hasVulnerabilities = Array.isArray(value.vulnerabilities);
  const metadata = isRecord(value.metadata) ? value.metadata as CycloneDxMetadata : null;
  const hasMetadataComponent = isRecord(metadata?.component);

  return hasSpecVersion && (hasComponents || hasVulnerabilities || hasMetadataComponent);
};

export const parseCycloneDxJson = (
  bom: CycloneDxBom,
  options: ParseSbomJsonOptions
): NormalizedSbomDocument => {
  const vulnerabilityIndex = buildVulnerabilityIndex(bom);
  const components = flattenComponents(bom).map((component, index) => {
    const name = getTrimmedString(component.name) ?? `Unnamed component ${index + 1}`;
    const version = getTrimmedString(component.version);
    const componentRef = getTrimmedString(component['bom-ref']);
    const vulnerabilities = componentRef
      ? [...(vulnerabilityIndex.get(componentRef) ?? [])]
      : [];
    const highestSeverity = getHighestSeverity(vulnerabilities);
    const supplier = isRecord(component.supplier)
      ? getTrimmedString((component.supplier as CycloneDxSupplier).name)
      : undefined;
    const purl = getTrimmedString(component.purl);
    const cpe = getTrimmedString(component.cpe);

    const normalized: NormalizedComponent = {
      cweGroups: buildCweGroups(vulnerabilities),
      dataview: vulnerabilities.length > 0 ? buildDataviewFields(vulnerabilities) : buildEmptyDataviewFields(),
      id: componentRef ?? `${name}@${version ?? 'unknown'}#${index}`,
      name,
      vulnerabilities,
      vulnerabilityCount: vulnerabilities.length
    };

    if (version) {
      normalized.version = version;
    }
    if (supplier) {
      normalized.supplier = supplier;
    }

    const license = getPrimaryLicense(component);
    if (license) {
      normalized.license = license;
    }
    if (purl) {
      normalized.purl = purl;
    }
    if (cpe) {
      normalized.cpe = cpe;
    }
    if (highestSeverity) {
      normalized.highestSeverity = highestSeverity;
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

  const metadata = isRecord(bom.metadata) ? (bom.metadata as CycloneDxMetadata) : null;
  const metadataComponent = isRecord(metadata?.component)
    ? (metadata.component as CycloneDxComponent)
    : undefined;

  return {
    components,
    format: 'cyclonedx',
    name: getTrimmedString(metadataComponent?.name) ?? options.source.basename,
    sourcePath: options.source.path
  };
};
