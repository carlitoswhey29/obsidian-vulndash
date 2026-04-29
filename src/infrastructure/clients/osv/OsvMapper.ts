import type {
  Vulnerability,
  VulnerabilityAffectedPackage,
  VulnerabilityMetadata,
  VulnerabilitySourceUrls
} from '../../../domain/entities/Vulnerability';
import type { Severity } from '../../../domain/value-objects/Severity';
import { classifySeverity } from '../../../domain/value-objects/CvssScore';
import { parseCvssScore } from '../../../domain/services/CvssVectorParser';
import { PurlNormalizer } from '../../../domain/services/PurlNormalizer';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../security/sanitize';
import type { OsvAffectedPayload, OsvSeverityPayload, OsvVulnerabilityPayload } from './OsvTypes';

const OSV_HTML_URL_PREFIX = 'https://osv.dev/vulnerability/';
const OSV_API_URL_PREFIX = 'https://api.osv.dev/v1/vulns/';

const severityToRepresentativeScore = (severity: Severity): number => {
  switch (severity) {
    case 'CRITICAL':
      return 9.5;
    case 'HIGH':
      return 8;
    case 'MEDIUM':
      return 5.5;
    case 'LOW':
      return 2.5;
    case 'NONE':
    default:
      return 0;
  }
};

const uniqueNonEmpty = (values: readonly string[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const trimmed = sanitizeText(value);
    if (!trimmed) {
      continue;
    }

    const key = trimmed.toLowerCase();
    if (seen.has(key)) {
      continue;
    }

    seen.add(key);
    result.push(trimmed);
  }

  return result;
};

const normalizeSeverityLabel = (value: string | undefined): Severity | undefined => {
  const normalized = sanitizeText(value ?? '').toLowerCase();
  switch (normalized) {
    case 'critical':
      return 'CRITICAL';
    case 'high':
      return 'HIGH';
    case 'medium':
    case 'moderate':
      return 'MEDIUM';
    case 'low':
      return 'LOW';
    case 'none':
    case 'informational':
    case 'info':
    case 'unknown':
    case 'unscored':
      return 'NONE';
    default:
      return undefined;
  }
};

const extractNumericCvssScore = (severity: OsvSeverityPayload): number | undefined => {
  if (!severity.type.toUpperCase().startsWith('CVSS')) {
    return undefined;
  }

  return parseCvssScore(severity.score, severity.type);
};

const collectSeverityPayloads = (payload: OsvVulnerabilityPayload): OsvSeverityPayload[] => [
  ...(payload.severity ?? []),
  ...(payload.affected ?? []).flatMap((affected) => affected.severity ?? [])
];

const resolveSeverity = (payload: OsvVulnerabilityPayload): { cvssScore: number; severity: Severity } => {
  for (const severityPayload of collectSeverityPayloads(payload)) {
    const cvssScore = extractNumericCvssScore(severityPayload);
    if (cvssScore !== undefined) {
      return {
        cvssScore,
        severity: classifySeverity(cvssScore)
      };
    }
  }

  const databaseSpecificSeverity = normalizeSeverityLabel(
    payload.database_specific?.severity
    ?? payload.affected?.find((affected) => affected.database_specific?.severity)?.database_specific?.severity
  );
  if (databaseSpecificSeverity) {
    return {
      cvssScore: severityToRepresentativeScore(databaseSpecificSeverity),
      severity: databaseSpecificSeverity
    };
  }

  const fallbackSeverity = normalizeSeverityLabel(
    collectSeverityPayloads(payload)
      .map((severityPayload) => severityPayload.score)
      .find((value) => normalizeSeverityLabel(value) !== undefined)
    ?? payload.affected?.find((affected) => normalizeSeverityLabel(affected.ecosystem_specific?.severity) !== undefined)?.ecosystem_specific?.severity
  );
  if (fallbackSeverity) {
    return {
      cvssScore: severityToRepresentativeScore(fallbackSeverity),
      severity: fallbackSeverity
    };
  }

  return {
    cvssScore: 0,
    severity: 'NONE'
  };
};

const stripPurlVersion = (purl: string): string => {
  const hashIndex = purl.indexOf('#');
  const withoutSubpath = hashIndex >= 0 ? purl.slice(0, hashIndex) : purl;
  const queryIndex = withoutSubpath.indexOf('?');
  const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
  const lastAt = withoutQualifiers.lastIndexOf('@');
  const lastSlash = withoutQualifiers.lastIndexOf('/');

  if (lastAt > lastSlash) {
    return withoutQualifiers.slice(0, lastAt);
  }

  return withoutQualifiers;
};

const extractPurlVersion = (purl: string): string | undefined => {
  const hashIndex = purl.indexOf('#');
  const withoutSubpath = hashIndex >= 0 ? purl.slice(0, hashIndex) : purl;
  const queryIndex = withoutSubpath.indexOf('?');
  const withoutQualifiers = queryIndex >= 0 ? withoutSubpath.slice(0, queryIndex) : withoutSubpath;
  const lastAt = withoutQualifiers.lastIndexOf('@');
  const lastSlash = withoutQualifiers.lastIndexOf('/');

  if (lastAt > lastSlash && lastAt < withoutQualifiers.length - 1) {
    return withoutQualifiers.slice(lastAt + 1);
  }

  return undefined;
};

const buildVersionRange = (affected: OsvAffectedPayload): string | undefined => {
  const ranges = (affected.ranges ?? []).flatMap((range) => range.events.map((event) => ({
    introduced: sanitizeText(event.introduced ?? ''),
    fixed: sanitizeText(event.fixed ?? ''),
    lastAffected: sanitizeText(event.last_affected ?? ''),
    limit: sanitizeText(event.limit ?? '')
  })));

  const parts = uniqueNonEmpty(ranges.flatMap((range) => [
    range.introduced && range.introduced !== '0' ? `>= ${range.introduced}` : '',
    range.fixed ? `< ${range.fixed}` : '',
    range.lastAffected ? `<= ${range.lastAffected}` : '',
    range.limit ? `limit ${range.limit}` : ''
  ]));

  if (parts.length > 0) {
    return parts.join(', ');
  }

  const versions = uniqueNonEmpty((affected.versions ?? []).map((version) => sanitizeText(version)));
  if (versions.length > 0) {
    return versions.join(', ');
  }

  return undefined;
};

const toAffectedPackage = (affected: OsvAffectedPayload): VulnerabilityAffectedPackage | null => {
  const normalizedPurl = PurlNormalizer.normalize(affected.package?.purl);
  const packageName = sanitizeText(affected.package?.name ?? '');
  const ecosystem = sanitizeText(affected.package?.ecosystem ?? '');

  if (!normalizedPurl && !packageName) {
    return null;
  }

  const version = normalizedPurl ? extractPurlVersion(normalizedPurl) : undefined;
  const vulnerableVersionRange = buildVersionRange(affected);

  return {
    name: packageName || stripPurlVersion(normalizedPurl ?? ''),
    ...(ecosystem ? { ecosystem } : {}),
    ...(normalizedPurl ? { purl: normalizedPurl } : {}),
    ...(version ? { version } : {}),
    ...(vulnerableVersionRange ? { vulnerableVersionRange } : {})
  };
};

const buildStableId = (payload: OsvVulnerabilityPayload): string => {
  const explicitId = sanitizeText(payload.id ?? '');
  if (explicitId) {
    return explicitId;
  }

  const aliasId = uniqueNonEmpty(payload.aliases ?? [])[0];
  if (aliasId) {
    return aliasId;
  }

  const summary = sanitizeText(payload.summary ?? payload.details ?? '');
  const modified = sanitizeText(payload.modified ?? payload.published ?? '');
  return summary || modified || 'unknown';
};

export class OsvMapper {
  public constructor(private readonly sourceName: string) {}

  public normalize(payload: OsvVulnerabilityPayload): Vulnerability {
    const id = buildStableId(payload);
    const publishedAt = sanitizeText(payload.published ?? payload.modified ?? new Date(0).toISOString());
    const updatedAt = sanitizeText(payload.modified ?? publishedAt);
    const title = sanitizeText(payload.summary ?? id ?? 'OSV Advisory');
    const summary = sanitizeMarkdown(payload.details ?? payload.summary ?? 'No summary provided');
    const { cvssScore, severity } = resolveSeverity(payload);

    const affectedPackages = (payload.affected ?? [])
      .map((affected) => toAffectedPackage(affected))
      .filter((affectedPackage): affectedPackage is VulnerabilityAffectedPackage => affectedPackage !== null);
    const affectedProducts = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const aliases = uniqueNonEmpty(payload.aliases ?? []);
    const related = uniqueNonEmpty(payload.related ?? []);
    const upstream = uniqueNonEmpty(payload.upstream ?? []);
    const identifiers = uniqueNonEmpty([id, ...aliases, ...related, ...upstream]);
    const packages = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const vulnerableVersionRanges = uniqueNonEmpty(affectedPackages
      .map((affectedPackage) => affectedPackage.vulnerableVersionRange
        ? `${affectedPackage.name}: ${affectedPackage.vulnerableVersionRange}`
        : ''));

    const apiUrl = sanitizeUrl(`${OSV_API_URL_PREFIX}${encodeURIComponent(id)}`);
    const htmlUrl = sanitizeUrl(`${OSV_HTML_URL_PREFIX}${encodeURIComponent(id)}`);
    const sourceUrl = sanitizeUrl(payload.database_specific?.source ?? '');
    const references = uniqueNonEmpty([
      htmlUrl,
      sourceUrl,
      ...(payload.references ?? []).map((reference) => sanitizeUrl(reference.url))
    ]);

    const sourceUrls: VulnerabilitySourceUrls = {};
    if (apiUrl) {
      sourceUrls.api = apiUrl;
    }
    if (htmlUrl) {
      sourceUrls.html = htmlUrl;
    }
    if (sourceUrl) {
      sourceUrls.repositoryAdvisory = sourceUrl;
    }

    const metadata: VulnerabilityMetadata = {};
    const cveId = identifiers.find((identifier) => identifier.toUpperCase().startsWith('CVE-'));
    if (cveId) {
      metadata.cveId = cveId;
    }
    if (identifiers.length > 0) {
      metadata.identifiers = identifiers;
    }
    const metadataAliases = uniqueNonEmpty(aliases.filter((alias) => alias !== cveId && alias !== id));
    if (metadataAliases.length > 0) {
      metadata.aliases = metadataAliases;
    }
    if (packages.length > 0) {
      metadata.packages = packages;
    }
    if (affectedPackages.length > 0) {
      metadata.affectedPackages = affectedPackages;
    }
    if (vulnerableVersionRanges.length > 0) {
      metadata.vulnerableVersionRanges = vulnerableVersionRanges;
    }
    if (Object.keys(sourceUrls).length > 0) {
      metadata.sourceUrls = sourceUrls;
    }

    return {
      id,
      source: this.sourceName,
      title,
      summary,
      publishedAt,
      updatedAt,
      cvssScore,
      severity,
      references,
      affectedProducts,
      ...(Object.keys(metadata).length > 0 ? { metadata } : {})
    };
  }
}
