import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { MarkdownBuilder } from '../../infrastructure/obsidian/MarkdownBuilder';
import { VulnerabilityMarkdownSupport } from './VulnerabilityMarkdownSupport';

export interface DailyRollupFindingInput {
  vulnerability: Vulnerability;
  affectedProjects?: Array<{
    target: string;
    displayName?: string
  }>;
  matchedComponents?: Array<{
    name: string;
    version?: string;
    ecosystem?: string;
  }>;
  triageState?: string;
  rationale?: string;
}

export interface DailyRollupMarkdownComposerInput {
  generatedAt: string;
  dateLabel: string;
  findings: DailyRollupFindingInput[];
  title?: string;
  summary?: string;
}

export class DailyRollupMarkdownComposer {
  public constructor(
    private readonly support: VulnerabilityMarkdownSupport = new VulnerabilityMarkdownSupport()
  ) {}

  public compose(input: DailyRollupMarkdownComposerInput): string {
    const builder = new MarkdownBuilder();
    const title = input.title?.trim() || `Daily Rollup - ${input.dateLabel}`;

    const sortedFindings = [...input.findings].sort((left, right) => {
      const severityCompare = this.support.compareSeverity(
        String(left.vulnerability.severity),
        String(right.vulnerability.severity)
      );

      if (severityCompare !== 0) {
        return severityCompare;
      }

      return left.vulnerability.updatedAt.localeCompare(right.vulnerability.updatedAt) * -1;
    });

    builder.h1(title);

    builder.callout('summary', 'Rollup Summary', [
      `Generated At: ${input.generatedAt}`,
      `Findings: ${MarkdownBuilder.bold(String(sortedFindings.length))}`,
      `Critical / High: ${MarkdownBuilder.bold(String(this.countCriticalHigh(sortedFindings)))}`
    ]);

    if (input.summary?.trim()) {
      builder.paragraph(input.summary.trim());
    }

    if (sortedFindings.length === 0) {
      builder.callout('success', 'No Findings Selected', [
        'No findings met the current rollup selection criteria.'
      ]);
      return builder.build();
    }

    builder.h2('Findings Overview');
    builder.table({
      headers: ['Severity', 'Identifier', 'Title', 'Projects', 'Components'],
      rows: sortedFindings.map((finding) => [
        finding.vulnerability.severity,
        this.support.formatVulnerabilityLink(
          finding.vulnerability,
          this.support.getPrimaryIdentifier(finding.vulnerability)
        ),
        finding.vulnerability.title,
        this.formatProjectSummary(finding.affectedProjects),
        this.formatComponentSummary(finding.matchedComponents)
      ])
    });

    builder.h2('Detailed Findings');

    for (const finding of sortedFindings) {
      const vulnerability = finding.vulnerability;
      const identifier = this.support.getPrimaryIdentifier(vulnerability) ?? vulnerability.id;

      builder.h3(identifier);

      builder.callout(
        this.support.getSeverityCalloutType(String(vulnerability.severity)),
        'Finding Summary',
        [
          `Severity: ${MarkdownBuilder.bold(String(vulnerability.severity))}`,
          `Title: ${vulnerability.title}`,
          `Published: ${vulnerability.publishedAt}`,
          `Updated: ${vulnerability.updatedAt}`,
          ...(finding.triageState ? [`Triage: ${finding.triageState}`] : [])
        ]
      );

      if (vulnerability.summary.trim()) {
        builder.paragraph(vulnerability.summary.trim());
      }

      const metadata = this.support.buildMetadataItems(vulnerability);
      if (metadata.length > 0) {
        builder.definitionList(metadata);
      }

      if (finding.rationale?.trim()) {
        builder.h4('Selection Rationale');
        builder.paragraph(finding.rationale.trim());
      }

      const projectLinks = this.buildProjectLinks(finding.affectedProjects);
      if (projectLinks.length > 0) {
        builder.h4('Affected Projects');
        builder.unorderedList(projectLinks);
      }

      const componentLinks = this.buildComponentLinks(finding.matchedComponents);
      if (componentLinks.length > 0) {
        builder.h4('Matched Components');
        builder.unorderedList(componentLinks);
      }

      const packageRows = this.support.buildAffectedPackageTableRows(vulnerability);
      if (packageRows.length > 0) {
        builder.h4('Affected Packages');
        builder.table({
          headers: ['Package', 'Ecosystem', 'Vulnerable Range', 'First Patched', 'Vendor'],
          rows: packageRows.map((row) => [
            row.packageLink,
            row.ecosystem,
            row.vulnerableVersionRange,
            row.firstPatchedVersion,
            row.vendor
          ])
        });
      }

      const references = this.support.buildReferenceLinks(vulnerability);
      if (references.length > 0) {
        builder.h4('References');
        builder.unorderedList(references);
      }
    }

    return builder.build();
  }

  private buildProjectLinks(
    projects?: Array<{ target: string; displayName?: string }>
  ): string[] {
    if (!projects?.length) {
      return [];
    }

    return projects
      .map((project) =>
        this.support.formatProjectLink(project.target, project.displayName)
      )
      .filter((link) => link.length > 0);
  }

  private buildComponentLinks(
    components?: Array<{ name: string; version?: string; ecosystem?: string }>
  ): string[] {
    if (!components?.length) {
      return [];
    }

    return components
      .filter((component) => component.name.trim().length > 0)
      .map((component) => {
        const wikiLink = this.support.formatComponentLink(
          component.name,
          component.version,
          component.version ? `${component.name} ${component.version}` : component.name
        );

        return component.ecosystem ? `${wikiLink} (${component.ecosystem})` : wikiLink;
      });
  }

  private formatProjectSummary(
    projects?: Array<{ target: string; displayName?: string }>
  ): string {
    if (!projects?.length) {
      return 'None';
    }

    const seen = new Set<string>();
    const values: string[] = [];

    for (const project of projects) {
      const value = project.displayName?.trim() || project.target.trim();
      if (!value || seen.has(value)) {
        continue;
      }

      seen.add(value);
      values.push(value);
    }

    return values.join(', ') || 'None';
  }

  private formatComponentSummary(
    components?: Array<{ name: string; version?: string; ecosystem?: string }>
  ): string {
    if (!components?.length) {
      return 'None';
    }

    const values = components
      .filter((component) => component.name.trim().length > 0)
      .map((component) => component.version ? `${component.name} ${component.version}` : component.name);

    return values.join(', ') || 'None';
  }

  private countCriticalHigh(findings: DailyRollupFindingInput[]): number {
    return findings.filter((finding) => {
      const severity = String(finding.vulnerability.severity).toUpperCase();
      return severity === 'CRITICAL' || severity === 'HIGH';
    }).length;
  }
}
