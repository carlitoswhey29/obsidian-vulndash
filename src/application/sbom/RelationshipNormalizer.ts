import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type {
  ComponentRelationshipGraph,
  ComponentVulnerabilityLinkEvidence,
  ComponentVulnerabilityRelationship,
  RelatedComponentSummary,
  RelatedVulnerabilitySummary,
  TrackedComponent
} from './types';
import { ComponentIdentityService } from './ComponentIdentityService';

const evidenceRank: Record<ComponentVulnerabilityLinkEvidence, number> = {
  purl: 0,
  cpe: 1,
  'name-version': 2,
  explicit: 3
};

const compareStrings = (left: string, right: string): number =>
  left.localeCompare(right);

const compareOptionalStrings = (
  left: string | null | undefined,
  right: string | null | undefined
): number =>
  (left ?? '').localeCompare(right ?? '');

const severityRank = (severity: string): number => {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
};

export interface VulnerabilityIdentity {
  id: string;
  identifiers: string[];
  notePath?: string;
  ref: string;
  source: string;
}

export class RelationshipNormalizer {
  public constructor(
    private readonly identityService = new ComponentIdentityService()
  ) {}

  public buildVulnerabilityRef(vulnerability: Pick<Vulnerability, 'id' | 'source'>): string {
    return `${this.normalizeVulnerabilityToken(vulnerability.source)}::${this.normalizeVulnerabilityToken(vulnerability.id)}`;
  }

  public normalizeRelationshipGraph(
    relationships: readonly ComponentVulnerabilityRelationship[],
    componentsByKey: ReadonlyMap<string, TrackedComponent>,
    vulnerabilitiesByRef: ReadonlyMap<string, VulnerabilityIdentity & Pick<Vulnerability, 'cvssScore' | 'references' | 'severity' | 'title'>>
  ): ComponentRelationshipGraph {
    const dedupedByPair = new Map<string, ComponentVulnerabilityRelationship>();

    for (const relationship of relationships) {
      const normalized = this.normalizeRelationship(relationship);
      const pairKey = `${normalized.componentKey}||${normalized.vulnerabilityRef}`;
      const existing = dedupedByPair.get(pairKey);

      if (!existing || evidenceRank[normalized.evidence] < evidenceRank[existing.evidence]) {
        dedupedByPair.set(pairKey, normalized);
      }
    }

    const normalizedRelationships = Array.from(dedupedByPair.values()).sort((left, right) =>
      compareStrings(left.componentKey, right.componentKey)
      || compareStrings(left.vulnerabilityRef, right.vulnerabilityRef)
      || evidenceRank[left.evidence] - evidenceRank[right.evidence]
    );

    const componentsByVulnerability = new Map<string, RelatedComponentSummary[]>();
    const vulnerabilitiesByComponent = new Map<string, RelatedVulnerabilitySummary[]>();

    for (const relationship of normalizedRelationships) {
      const component = componentsByKey.get(relationship.componentKey);
      const vulnerability = vulnerabilitiesByRef.get(relationship.vulnerabilityRef);

      if (!component || !vulnerability) {
        continue;
      }

      const relatedComponent = this.toRelatedComponentSummary(component, relationship.evidence);
      const relatedVulnerability = this.toRelatedVulnerabilitySummary(vulnerability, relationship.evidence);

      const componentList = componentsByVulnerability.get(relationship.vulnerabilityRef) ?? [];
      componentList.push(relatedComponent);
      componentsByVulnerability.set(relationship.vulnerabilityRef, componentList);

      const vulnerabilityList = vulnerabilitiesByComponent.get(relationship.componentKey) ?? [];
      vulnerabilityList.push(relatedVulnerability);
      vulnerabilitiesByComponent.set(relationship.componentKey, vulnerabilityList);
    }

    for (const [key, entries] of componentsByVulnerability) {
      componentsByVulnerability.set(key, entries.sort((left, right) =>
        evidenceRank[left.evidence] - evidenceRank[right.evidence]
        || compareStrings(left.name, right.name)
        || compareOptionalStrings(left.version, right.version)
        || compareStrings(left.key, right.key)
      ));
    }

    for (const [key, entries] of vulnerabilitiesByComponent) {
      vulnerabilitiesByComponent.set(key, entries.sort((left, right) =>
        evidenceRank[left.evidence] - evidenceRank[right.evidence]
        || severityRank(right.severity) - severityRank(left.severity)
        || compareStrings(left.source, right.source)
        || compareStrings(left.id, right.id)
      ));
    }

    return {
      componentsByVulnerability,
      relationships: normalizedRelationships,
      vulnerabilitiesByComponent
    };
  }

  public buildVulnerabilityIdentity(vulnerability: Vulnerability, notePath?: string): VulnerabilityIdentity {
    const identifiers = new Set<string>([
      vulnerability.id,
      vulnerability.metadata?.cveId ?? '',
      vulnerability.metadata?.ghsaId ?? '',
      ...(vulnerability.metadata?.identifiers ?? []),
      ...(vulnerability.metadata?.aliases ?? [])
    ].map((value) => this.normalizeVulnerabilityToken(value)).filter(Boolean));

    return {
      id: vulnerability.id,
      identifiers: Array.from(identifiers).sort(compareStrings),
      ...(notePath ? { notePath } : {}),
      ref: this.buildVulnerabilityRef(vulnerability),
      source: vulnerability.source
    };
  }

  public buildPurlKey(value: string): string {
    return `purl:${this.identityService.normalizePurlValue(value)}`;
  }

  public buildCpeKey(value: string): string {
    return `cpe:${this.identityService.normalizeCpeValue(value)}`;
  }

  public buildNameVersionKey(name: string, version: string): string | null {
    return this.identityService.getNameVersionKeyFromParts(name, version);
  }

  public normalizeVulnerabilityToken(value: string): string {
    return value.trim().replace(/\s+/g, ' ').toLowerCase();
  }

  private normalizeRelationship(relationship: ComponentVulnerabilityRelationship): ComponentVulnerabilityRelationship {
    return {
      componentKey: relationship.componentKey.trim().toLowerCase(),
      evidence: relationship.evidence,
      vulnerabilityId: relationship.vulnerabilityId.trim(),
      vulnerabilityRef: relationship.vulnerabilityRef.trim().toLowerCase(),
      vulnerabilitySource: relationship.vulnerabilitySource.trim()
    };
  }

  private toRelatedComponentSummary(
    component: TrackedComponent,
    evidence: ComponentVulnerabilityLinkEvidence
  ): RelatedComponentSummary {
    const summary: RelatedComponentSummary = {
      evidence,
      key: component.key,
      name: component.name,
      vulnerabilityCount: component.vulnerabilityCount
    };

    if (component.version) {
      summary.version = component.version;
    }
    if (component.purl) {
      summary.purl = component.purl;
    }
    if (component.cpe) {
      summary.cpe = component.cpe;
    }
    if (component.notePath !== undefined) {
      summary.notePath = component.notePath;
    }
    if (component.highestSeverity) {
      summary.highestSeverity = component.highestSeverity;
    }

    return summary;
  }

  private toRelatedVulnerabilitySummary(
    vulnerability: VulnerabilityIdentity & Pick<Vulnerability, 'cvssScore' | 'references' | 'severity' | 'title'>,
    evidence: ComponentVulnerabilityLinkEvidence
  ): RelatedVulnerabilitySummary {
    const summary: RelatedVulnerabilitySummary = {
      cvssScore: vulnerability.cvssScore,
      evidence,
      id: vulnerability.id,
      referenceCount: vulnerability.references.length,
      severity: vulnerability.severity,
      source: vulnerability.source,
      title: vulnerability.title
    };

    if (vulnerability.notePath) {
      summary.notePath = vulnerability.notePath;
    }

    return summary;
  }
}
