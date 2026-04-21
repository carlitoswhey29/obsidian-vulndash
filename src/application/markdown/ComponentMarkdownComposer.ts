import type { Vulnerability, VulnerabilityAffectedPackage } from '../../domain/entities/Vulnerability';
import { MarkdownBuilder } from '../../infrastructure/obsidian/MarkdownBuilder';
import { VulnerabilityMarkdownSupport } from './VulnerabilityMarkdownSupport';

export interface ComponentMarkdownComposerInput {
  componentName: string;
  componentVersion?: string;
  ecosystem?: string;
  purl?: string;
  cpe?: string;
  vendor?: string;
  sourceCodeLocation?: string;
  description?: string;
  vulnerabilities: Vulnerability[];
}

interface MatchingAffectedPackage {
  vulnerability: Vulnerability;
  affectedPackage: VulnerabilityAffectedPackage;
}

export class ComponentMarkdownComposer {
  public constructor(
    private readonly support: VulnerabilityMarkdownSupport = new VulnerabilityMarkdownSupport()
  ) {}

  public compose(input: ComponentMarkdownComposerInput): string {
    const builder = new MarkdownBuilder();
    const componentTitle = input.componentVersion
      ? `${input.componentName} ${input.componentVersion}`
      : input.componentName;

    const matchedPackages = this.findMatchingAffectedPackages(input);
    const relatedVulnerabilities = this.getRelatedVulnerabilities(input.vulnerabilities, matchedPackages);

    builder.h2(componentTitle);

    builder.callout('summary', 'Component Overview', [
      `Component: ${MarkdownBuilder.bold(input.componentName)}`,
      ...(input.componentVersion ? [`Version: ${MarkdownBuilder.inlineCode(input.componentVersion)}`] : []),
      ...(input.ecosystem ? [`Ecosystem: ${input.ecosystem}`] : []),
      `Related Vulnerabilities: ${MarkdownBuilder.bold(String(relatedVulnerabilities.length))}`
    ]);

    if (input.description?.trim()) {
      builder.paragraph(input.description.trim());
    }

    const metadataItems = this.buildMetadataItems(input);
    if (metadataItems.length > 0) {
      builder.h3('Metadata');
      builder.definitionList(metadataItems);
    }

    if (matchedPackages.length > 0) {
      builder.h3('Affected Package Matches');
      builder.table({
        headers: ['Vulnerability', 'Package', 'Affected Range', 'First Patched', 'Vendor'],
        rows: matchedPackages.map(({ vulnerability, affectedPackage }) => [
          this.support.formatVulnerabilityLink(vulnerability, this.support.getPrimaryIdentifier(vulnerability)),
          this.support.formatComponentLink(
            affectedPackage.name,
            affectedPackage.version,
            affectedPackage.version
              ? `${affectedPackage.name} ${affectedPackage.version}`
              : affectedPackage.name
          ),
          affectedPackage.vulnerableVersionRange ?? 'Unknown',
          affectedPackage.firstPatchedVersion ?? 'Unknown',
          affectedPackage.vendor ?? 'Unknown'
        ])
      });
    }

    if (relatedVulnerabilities.length > 0) {
      builder.h3('Related Vulnerabilities');
      builder.table({
        headers: ['ID', 'Severity', 'Title', 'Published', 'Updated'],
        rows: relatedVulnerabilities.map((vulnerability) => [
          this.support.formatVulnerabilityLink(
            vulnerability,
            this.support.getPrimaryIdentifier(vulnerability)
          ),
          vulnerability.severity,
          vulnerability.title,
          vulnerability.publishedAt,
          vulnerability.updatedAt
        ])
      });

      for (const vulnerability of relatedVulnerabilities) {
        builder.h4(this.support.getPrimaryIdentifier(vulnerability) ?? vulnerability.id);

        builder.callout(
          this.support.getSeverityCalloutType(String(vulnerability.severity)),
          'Vulnerability Snapshot',
          [
            `Severity: ${MarkdownBuilder.bold(String(vulnerability.severity))}`,
            `Published: ${vulnerability.publishedAt}`,
            `Updated: ${vulnerability.updatedAt}`
          ]
        );

        if (vulnerability.summary.trim()) {
          builder.paragraph(vulnerability.summary.trim());
        }

        const metadataItems = this.support.buildMetadataItems(vulnerability);
        if (metadataItems.length > 0) {
          builder.definitionList(metadataItems);
        }

        const references = this.support.buildReferenceLinks(vulnerability);
        if (references.length > 0) {
          builder.unorderedList(references);
        }
      }
    } else {
      builder.callout('info', 'No Correlated Vulnerabilities', [
        'No vulnerabilities were matched to this component using the current component identity and affected package metadata.'
      ]);
    }

    return builder.build();
  }

  private buildMetadataItems(
    input: ComponentMarkdownComposerInput
  ): Array<{ term: string; description: string }> {
    const items: Array<{ term: string; description: string }> = [];

    if (input.ecosystem) {
      items.push({ term: 'Ecosystem', description: input.ecosystem });
    }

    if (input.vendor) {
      items.push({ term: 'Vendor', description: input.vendor });
    }

    if (input.purl) {
      items.push({ term: 'PURL', description: MarkdownBuilder.inlineCode(input.purl) });
    }

    if (input.cpe) {
      items.push({ term: 'CPE', description: MarkdownBuilder.inlineCode(input.cpe) });
    }

    if (input.sourceCodeLocation) {
      items.push({
        term: 'Source Code',
        description: MarkdownBuilder.link(input.sourceCodeLocation, input.sourceCodeLocation)
      });
    }

    return items;
  }

  private findMatchingAffectedPackages(
    input: ComponentMarkdownComposerInput
  ): MatchingAffectedPackage[] {
    const componentName = input.componentName.trim().toLowerCase();
    const componentVersion = input.componentVersion?.trim().toLowerCase();
    const componentPurl = input.purl?.trim().toLowerCase();
    const componentCpe = input.cpe?.trim().toLowerCase();

    const matches: MatchingAffectedPackage[] = [];

    for (const vulnerability of input.vulnerabilities) {
      const affectedPackages = vulnerability.metadata?.affectedPackages ?? [];

      for (const affectedPackage of affectedPackages) {
        const packageName = affectedPackage.name.trim().toLowerCase();
        const packageVersion = affectedPackage.version?.trim().toLowerCase();
        const packagePurl = affectedPackage.purl?.trim().toLowerCase();
        const packageCpe = affectedPackage.cpe?.trim().toLowerCase();

        const nameMatches = packageName === componentName;
        const versionMatches = !componentVersion || !packageVersion || packageVersion === componentVersion;
        const purlMatches = !!componentPurl && !!packagePurl && componentPurl === packagePurl;
        const cpeMatches = !!componentCpe && !!packageCpe && componentCpe === packageCpe;

        if ((nameMatches && versionMatches) || purlMatches || cpeMatches) {
          matches.push({
            vulnerability,
            affectedPackage
          });
        }
      }
    }

    return matches;
  }

  private getRelatedVulnerabilities(
    vulnerabilities: Vulnerability[],
    matchedPackages: MatchingAffectedPackage[]
  ): Vulnerability[] {
    const matchedIds = new Set(matchedPackages.map((entry) => entry.vulnerability.id));
    return vulnerabilities.filter((vulnerability) => matchedIds.has(vulnerability.id));
  }
}
