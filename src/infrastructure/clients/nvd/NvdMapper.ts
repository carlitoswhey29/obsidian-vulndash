import type {
  Vulnerability,
  VulnerabilityAffectedPackage,
  VulnerabilityMetadata,
  VulnerabilitySourceUrls
} from '../../../domain/entities/Vulnerability';
import { classifySeverity } from '../../../domain/value-objects/CvssScore';
import { ProductNameNormalizer } from '../../../domain/services/ProductNameNormalizer';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../security/sanitize';
import type {
  NvdConfigurationNode,
  NvdCpeMatch,
  NvdCveRecord,
  ParsedCpe
} from './NvdTypes';

const uniqueNonEmpty = (values: string[]): string[] => {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(trimmed);
  }

  return result;
};

const cleanCpeToken = (token: string): string => {
  if (!token || token === '*' || token === '-') {
    return '';
  }

  return token
    .replace(/\\([\\:*?!])/g, '$1')
    .replace(/_/g, ' ')
    .trim();
};

const buildVersionRange = (match: NvdCpeMatch, version: string): string => {
  const parts = [
    version,
    match.versionStartIncluding ? `>= ${match.versionStartIncluding}` : '',
    match.versionStartExcluding ? `> ${match.versionStartExcluding}` : '',
    match.versionEndIncluding ? `<= ${match.versionEndIncluding}` : '',
    match.versionEndExcluding ? `< ${match.versionEndExcluding}` : ''
  ].filter(Boolean);

  return parts.join(', ');
};

const toSentenceTitle = (description: string, cveId: string): string => {
  const normalized = sanitizeText(description);
  if (!normalized || normalized === 'No summary provided') {
    return cveId || 'Unknown CVE';
  }

  const firstSentence = normalized.split(/(?<=[.!?])\s+/)[0] ?? normalized;
  const titleSource = firstSentence.length >= 24 ? firstSentence : normalized;
  if (titleSource.length <= 120) {
    return titleSource;
  }

  const truncated = titleSource.slice(0, 117);
  const lastSpace = truncated.lastIndexOf(' ');
  const safeBoundary = lastSpace >= 60 ? lastSpace : truncated.length;
  return `${truncated.slice(0, safeBoundary).trimEnd()}...`;
};

export class NvdMapper {
  private readonly productNameNormalizer = new ProductNameNormalizer();

  public constructor(private readonly sourceName: string) {}

  public normalize(cve: NvdCveRecord): Vulnerability {
    const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore
      ?? cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore
      ?? cve.metrics?.cvssMetricV2?.[0]?.cvssData?.baseScore
      ?? 0;

    const description = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? 'No summary provided';
    const refs = (cve.references ?? []).map((r) => sanitizeUrl(r.url ?? '')).filter(Boolean);

    const cpeMatches = this.collectCpeMatches(cve.configurations ?? []);
    const affectedProducts = cpeMatches
      .map((match) => this.productNameNormalizer.normalize(sanitizeText(match.criteria ?? '')))
      .filter(Boolean);

    const affectedPackages = cpeMatches
      .map((match): VulnerabilityAffectedPackage | null => this.toAffectedPackage(match))
      .filter((affectedPackage): affectedPackage is VulnerabilityAffectedPackage => affectedPackage !== null);

    const cwes = uniqueNonEmpty(
      (cve.weaknesses ?? [])
        .flatMap((weakness) => weakness.description ?? [])
        .filter((descriptionItem) => descriptionItem.lang === 'en')
        .map((descriptionItem) => sanitizeText(descriptionItem.value ?? ''))
        .filter((cwe) => /^CWE-\d+$/i.test(cwe))
    );

    const vendors = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.vendor ?? ''));
    const packages = uniqueNonEmpty(affectedPackages.map((affectedPackage) => affectedPackage.name));
    const vulnerableVersionRanges = uniqueNonEmpty(
      affectedPackages.map((affectedPackage) =>
        affectedPackage.vulnerableVersionRange
          ? `${affectedPackage.vendor ? `${affectedPackage.vendor} ` : ''}${affectedPackage.name}: ${affectedPackage.vulnerableVersionRange}`
          : ''
      )
    );

    const publishedAt = cve.published ?? new Date(0).toISOString();
    const updatedAt = cve.lastModified ?? publishedAt;
    const cveId = sanitizeText(cve.id ?? '');
    const nvdUrl = cveId ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cveId)}` : '';

    const sourceUrls: VulnerabilitySourceUrls = {};
    if (nvdUrl) sourceUrls.html = nvdUrl;

    const metadata: VulnerabilityMetadata = {};
    if (cveId) {
      metadata.cveId = cveId;
      metadata.identifiers = [cveId];
    }
    if (cwes.length > 0) metadata.cwes = cwes;
    if (vendors.length > 0) metadata.vendors = vendors;
    if (packages.length > 0) metadata.packages = packages;
    if (affectedPackages.length > 0) metadata.affectedPackages = affectedPackages;
    if (vulnerableVersionRanges.length > 0) metadata.vulnerableVersionRanges = vulnerableVersionRanges;
    if (Object.keys(sourceUrls).length > 0) metadata.sourceUrls = sourceUrls;

    return {
      id: cveId || 'unknown',
      source: this.sourceName,
      title: toSentenceTitle(description, cveId || 'Unknown CVE'),
      summary: sanitizeMarkdown(description),
      publishedAt,
      updatedAt,
      cvssScore: score,
      severity: classifySeverity(score),
      references: uniqueNonEmpty([nvdUrl, ...refs]),
      affectedProducts: uniqueNonEmpty(affectedProducts),
      ...(Object.keys(metadata).length > 0 ? { metadata } : {})
    };
  }

  private collectCpeMatches(configurations: NonNullable<NvdCveRecord['configurations']>): NvdCpeMatch[] {
    const matches: NvdCpeMatch[] = [];

    const visitNode = (node: NvdConfigurationNode): void => {
      matches.push(...(node.cpeMatch ?? []).filter((match) => match.vulnerable !== false && Boolean(match.criteria)));
      for (const child of node.nodes ?? []) {
        visitNode(child);
      }
    };

    for (const configuration of configurations) {
      for (const node of configuration.nodes ?? []) {
        visitNode(node);
      }
    }

    return matches;
  }

  private parseCpe(criteria: string): ParsedCpe {
    const parts = criteria.split(':');
    return {
      vendor: cleanCpeToken(parts[3] ?? ''),
      product: cleanCpeToken(parts[4] ?? ''),
      version: cleanCpeToken(parts[5] ?? '')
    };
  }

  private toAffectedPackage(match: NvdCpeMatch): VulnerabilityAffectedPackage | null {
    const criteria = match.criteria ?? '';
    const parsed = this.parseCpe(criteria);
    const product = this.productNameNormalizer.normalize(parsed.product);

    if (!product) {
      return null;
    }

    const vendor = this.productNameNormalizer.normalize(parsed.vendor);
    const vulnerableVersionRange = buildVersionRange(match, parsed.version);

    return {
      ...(criteria ? { cpe: criteria } : {}),
      name: product,
      ...(vendor ? { vendor } : {}),
      ...(parsed.version && parsed.version !== '*' && parsed.version !== '-' ? { version: parsed.version } : {}),
      ...(vulnerableVersionRange ? { vulnerableVersionRange } : {})
    };
  }
}
