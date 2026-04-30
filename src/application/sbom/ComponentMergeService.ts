import type {
  NormalizedCweGroup,
  NormalizedSeverity,
  NormalizedVulnerability
} from '../../domain/sbom/types';
//import { PurlNormalizer } from '../../domain/services/PurlNormalizer';
import { getHighestSeverity, getSeverityRank } from '../../domain/value-objects/Severity';
import type { CatalogComponentInput, TrackedComponent, TrackedComponentSource } from './types';

const normalizeToken = (value: string): string =>
  value.trim().replace(/\s+/g, ' ').toLowerCase();

const compareOptionalStrings = (
  left: string | null | undefined,
  right: string | null | undefined
): number => {
  const leftValue = left?.trim() ?? '';
  const rightValue = right?.trim() ?? '';
  return leftValue.localeCompare(rightValue);
};

const pickDeterministicString = (
  left: string | undefined,
  right: string | undefined,
  options?: {
    preferLonger?: boolean;
  }
): string | undefined => {
  const leftValue = left?.trim();
  const rightValue = right?.trim();

  if (!leftValue) {
    return rightValue || undefined;
  }

  if (!rightValue) {
    return leftValue;
  }

  const leftNormalized = normalizeToken(leftValue);
  const rightNormalized = normalizeToken(rightValue);

  if (leftNormalized === rightNormalized) {
    if (options?.preferLonger && leftValue.length !== rightValue.length) {
      return leftValue.length >= rightValue.length ? leftValue : rightValue;
    }

    return leftValue.localeCompare(rightValue) <= 0 ? leftValue : rightValue;
  }

  if (options?.preferLonger && leftValue.length !== rightValue.length) {
    return leftValue.length > rightValue.length ? leftValue : rightValue;
  }

  return leftNormalized.localeCompare(rightNormalized) <= 0 ? leftValue : rightValue;
};

const pickNotePath = (
  left: string | null | undefined,
  right: string | null | undefined
): string | null | undefined => {
  const leftValue = left?.trim();
  const rightValue = right?.trim();

  if (!leftValue) {
    return rightValue ?? null;
  }

  if (!rightValue) {
    return leftValue;
  }

  return leftValue.localeCompare(rightValue) <= 0 ? leftValue : rightValue;
};

const pickHighestSeverity = (
  left: NormalizedSeverity | undefined,
  right: NormalizedSeverity | undefined
): NormalizedSeverity | undefined =>
  getHighestSeverity([left, right]);

const mergeNumbers = (left: readonly number[], right: readonly number[]): number[] =>
  Array.from(new Set([...left, ...right])).sort((first, second) => first - second);

const compareVulnerabilities = (
  left: NormalizedVulnerability,
  right: NormalizedVulnerability
): number => {
  const severityDiff = getSeverityRank(right.severity) - getSeverityRank(left.severity);
  if (severityDiff !== 0) {
    return severityDiff;
  }

  const scoreDiff = (right.score ?? -1) - (left.score ?? -1);
  if (scoreDiff !== 0) {
    return scoreDiff;
  }

  const idDiff = left.id.localeCompare(right.id);
  if (idDiff !== 0) {
    return idDiff;
  }

  return compareOptionalStrings(left.vector, right.vector);
};

const buildCweGroups = (
  vulnerabilities: readonly NormalizedVulnerability[]
): NormalizedCweGroup[] => {
  const groups = new Map<number, Set<string>>();

  for (const vulnerability of vulnerabilities) {
    for (const cwe of vulnerability.cwes) {
      const entries = groups.get(cwe) ?? new Set<string>();
      entries.add(vulnerability.id);
      groups.set(cwe, entries);
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

const getVulnerabilityKey = (vulnerability: NormalizedVulnerability): string => {
  const normalizedId = normalizeToken(vulnerability.id);
  if (normalizedId && normalizedId !== 'unknown-vulnerability') {
    return `id:${normalizedId}`;
  }

  const bomRef = vulnerability.bomRef?.trim();
  if (bomRef) {
    return `bom-ref:${normalizeToken(bomRef)}`;
  }

  const cwes = [...vulnerability.cwes].sort((left, right) => left - right).join(',');

  return [
    'fingerprint',
    normalizeToken(vulnerability.sourceName ?? ''),
    vulnerability.severity ?? '',
    normalizeToken(vulnerability.vector ?? ''),
    normalizeToken(vulnerability.published ?? ''),
    cwes,
    normalizeToken(vulnerability.description ?? '')
  ].join('|');
};

const mergeVulnerability = (
  left: NormalizedVulnerability,
  right: NormalizedVulnerability
): NormalizedVulnerability => {
  const merged: NormalizedVulnerability = {
    cwes: mergeNumbers(left.cwes, right.cwes),
    id: pickDeterministicString(left.id, right.id) ?? left.id
  };

  const bomRef = pickDeterministicString(left.bomRef, right.bomRef);
  if (bomRef) {
    merged.bomRef = bomRef;
  }

  const sourceName = pickDeterministicString(left.sourceName, right.sourceName);
  if (sourceName) {
    merged.sourceName = sourceName;
  }

  const sourceUrl = pickDeterministicString(left.sourceUrl, right.sourceUrl);
  if (sourceUrl) {
    merged.sourceUrl = sourceUrl;
  }

  const severity = pickHighestSeverity(left.severity, right.severity);
  if (severity) {
    merged.severity = severity;
  }

  const scoreCandidates = [left.score, right.score].filter((value): value is number => value !== undefined);
  if (scoreCandidates.length > 0) {
    merged.score = Math.max(...scoreCandidates);
  }

  const method = pickDeterministicString(left.method, right.method);
  if (method) {
    merged.method = method;
  }

  const vector = pickDeterministicString(left.vector, right.vector);
  if (vector) {
    merged.vector = vector;
  }

  const description = pickDeterministicString(left.description, right.description, { preferLonger: true });
  if (description) {
    merged.description = description;
  }

  const publishedCandidates = [left.published, right.published]
    .filter((value): value is string => Boolean(value?.trim()))
    .sort((first, second) => first.localeCompare(second));
  const earliestPublished = publishedCandidates[0];
  if (earliestPublished) {
    merged.published = earliestPublished;
  }

  const updatedCandidates = [left.updated, right.updated]
    .filter((value): value is string => Boolean(value?.trim()))
    .sort((first, second) => second.localeCompare(first));
  const latestUpdated = updatedCandidates[0];
  if (latestUpdated) {
    merged.updated = latestUpdated;
  }

  return merged;
};

const compareSourceRecords = (
  left: TrackedComponentSource,
  right: TrackedComponentSource
): number =>
  left.sourcePath.localeCompare(right.sourcePath)
  || left.format.localeCompare(right.format)
  || left.documentName.localeCompare(right.documentName)
  || left.name.localeCompare(right.name)
  || compareOptionalStrings(left.version, right.version)
  || left.componentId.localeCompare(right.componentId);

const getSourceRecordKey = (source: TrackedComponentSource): string =>
  [
    source.sourcePath,
    source.format,
    source.documentName,
    source.name,
    source.version ?? '',
    source.componentId
  ].join('|');

const compareFormats = (left: string, right: string): number =>
  left.localeCompare(right);

const compareSourceFiles = (left: string, right: string): number =>
  left.localeCompare(right);

export class ComponentMergeService {
  public createTrackedComponent(
    key: string,
    input: CatalogComponentInput
  ): TrackedComponent {
    const { component, document } = input;
    const source: TrackedComponentSource = {
      componentId: component.id,
      documentName: document.name,
      format: document.format,
      name: component.name,
      sourcePath: document.sourcePath
    };

    if (component.version) {
      source.version = component.version;
    }
    if (component.purl) {
      source.purl = component.purl;
    }
    if (component.cpe) {
      source.cpe = component.cpe;
    }
    if (component.notePath !== undefined) {
      source.notePath = component.notePath;
    }

    const tracked: TrackedComponent = {
      cweGroups: buildCweGroups(component.vulnerabilities),
      formats: [document.format],
      isEnabled: true,
      isFollowed: false,
      key,
      name: component.name,
      sourceFiles: [document.sourcePath],
      sources: [source],
      vulnerabilities: [...component.vulnerabilities].sort(compareVulnerabilities),
      vulnerabilityCount: component.vulnerabilities.length
    };

    if (component.version) {
      tracked.version = component.version;
    }
    if (component.purl) {
      tracked.purl = component.purl; //component.purl;
    }
    if (component.cpe) {
      tracked.cpe = component.cpe;
    }
    if (component.supplier) {
      tracked.supplier = component.supplier;
    }
    if (component.license) {
      tracked.license = component.license;
    }
    if (component.notePath !== undefined) {
      tracked.notePath = component.notePath;
    }
    if (component.highestSeverity) {
      tracked.highestSeverity = component.highestSeverity;
    }

    return tracked;
  }

  public mergeComponents(
    left: TrackedComponent,
    right: TrackedComponent
  ): TrackedComponent {
    const vulnerabilities = this.mergeVulnerabilities(left.vulnerabilities, right.vulnerabilities);
    const merged: TrackedComponent = {
      cweGroups: buildCweGroups(vulnerabilities),
      formats: Array.from(new Set([...left.formats, ...right.formats])).sort(compareFormats),
      isEnabled: left.isEnabled && right.isEnabled,
      isFollowed: left.isFollowed || right.isFollowed,
      key: left.key,
      name: pickDeterministicString(left.name, right.name) ?? left.name,
      sourceFiles: Array.from(new Set([...left.sourceFiles, ...right.sourceFiles])).sort(compareSourceFiles),
      sources: this.mergeSources(left.sources, right.sources),
      vulnerabilities,
      vulnerabilityCount: vulnerabilities.length
    };

    const version = pickDeterministicString(left.version, right.version);
    if (version) {
      merged.version = version;
    }

    const purl = pickDeterministicString(left.purl, right.purl);
    if (purl) {
      merged.purl = purl;
    }

    const cpe = pickDeterministicString(left.cpe, right.cpe);
    if (cpe) {
      merged.cpe = cpe;
    }

    const supplier = pickDeterministicString(left.supplier, right.supplier);
    if (supplier) {
      merged.supplier = supplier;
    }

    const license = pickDeterministicString(left.license, right.license);
    if (license) {
      merged.license = license;
    }

    const notePath = pickNotePath(left.notePath, right.notePath);
    if (notePath !== undefined) {
      merged.notePath = notePath;
    }

    const highestSeverity = getHighestSeverity([
      left.highestSeverity,
      right.highestSeverity,
      ...vulnerabilities.map((vulnerability) => vulnerability.severity)
    ]);
    if (highestSeverity) {
      merged.highestSeverity = highestSeverity;
    }

    return merged;
  }

  private mergeSources(
    left: readonly TrackedComponentSource[],
    right: readonly TrackedComponentSource[]
  ): TrackedComponentSource[] {
    const deduped = new Map<string, TrackedComponentSource>();

    for (const source of [...left, ...right]) {
      deduped.set(getSourceRecordKey(source), source);
    }

    return Array.from(deduped.values()).sort(compareSourceRecords);
  }

  private mergeVulnerabilities(
    left: readonly NormalizedVulnerability[],
    right: readonly NormalizedVulnerability[]
  ): NormalizedVulnerability[] {
    const deduped = new Map<string, NormalizedVulnerability>();

    for (const vulnerability of [...left, ...right]) {
      const key = getVulnerabilityKey(vulnerability);
      const existing = deduped.get(key);
      deduped.set(key, existing ? mergeVulnerability(existing, vulnerability) : vulnerability);
    }

    return Array.from(deduped.values()).sort(compareVulnerabilities);
  }
}
