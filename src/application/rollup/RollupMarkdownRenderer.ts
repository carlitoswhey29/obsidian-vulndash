import type { RollupFinding } from '../../domain/rollup/RollupFinding';
import { formatTriageStateLabel } from '../../domain/triage/TriageState';
import {
  DailyRollupMarkdownComposer,
  type DailyRollupFindingInput,
  type DailyRollupMarkdownComposerInput
} from '../markdown/DailyRollupMarkdownComposer';

export interface ManagedMarkdownSection {
  readonly content: string;
  readonly key: string;
}

export interface RenderedDailyRollup {
  readonly analystNotesHeading: string;
  readonly analystNotesPlaceholder: string;
  readonly managedSections: readonly ManagedMarkdownSection[];
  readonly title: string;
}

const asSentence = (value: string): string => {
  const normalized = value.trim();
  if (!normalized) {
    return '';
  }

  return /[.!?]$/.test(normalized) ? normalized : `${normalized}.`;
};

const truncateInline = (value: string, maxLength = 180): string => {
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`;
};

const safeInline = (value: string | null | undefined, fallback = 'Not provided'): string => {
  const normalized = value?.replace(/\s+/g, ' ').trim();
  return normalized && normalized.length > 0 ? normalized : fallback;
};

export class RollupMarkdownRenderer {
  public constructor(
    private readonly composer: DailyRollupMarkdownComposer = new DailyRollupMarkdownComposer()
  ) {}

  public render(input: {
    readonly date: string;
    readonly findings: readonly RollupFinding[];
  }): RenderedDailyRollup {
    const composerInput = this.mapToComposerInput(input.date, input.findings);
    const composedMarkdown = this.composer.compose(composerInput);
    const title = `# ${composerInput.title ?? `Daily Rollup - ${input.date}`}`;
    const body = this.stripLeadingTitleHeading(composedMarkdown, title);

    return {
      analystNotesHeading: '## Analyst Notes',
      analystNotesPlaceholder: '- Add analyst notes, escalation context, and follow-up decisions here.',
      managedSections: [
        {
          key: 'daily-rollup',
          content: body
        }
      ],
      title
    };
  }

  private mapToComposerInput(
    date: string,
    findings: readonly RollupFinding[]
  ): DailyRollupMarkdownComposerInput {
    const sortedFindings = this.sortFindings(findings);

    return {
      generatedAt: date,
      dateLabel: date,
      title: `VulnDash Briefing ${date}`,
      summary: this.buildSummary(sortedFindings),
      findings: sortedFindings.map((finding) => this.mapFinding(finding))
    };
  }

  private mapFinding(finding: RollupFinding): DailyRollupFindingInput {
    const matchedComponents = this.extractMatchedComponents(finding);

    return {
      vulnerability: finding.vulnerability,
      affectedProjects: finding.affectedProjects
        .map((project) => {
          const target = project.notePath.trim();
          const displayName = project.displayName?.trim();

          return {
            target,
            ...(displayName ? { displayName } : {})
          };
        })
        .filter((project) => project.target.length > 0),
      triageState: formatTriageStateLabel(finding.triageState),
      rationale: this.buildFindingRationale(finding),
      ...(matchedComponents ? { matchedComponents } : {})
    };
  }

  private extractMatchedComponents(
    finding: RollupFinding
  ): DailyRollupFindingInput['matchedComponents'] {
    const affectedPackages = finding.vulnerability.metadata?.affectedPackages ?? [];
    if (affectedPackages.length === 0) {
      return undefined;
    }

    const seen = new Set<string>();
    const components: NonNullable<DailyRollupFindingInput['matchedComponents']> = [];

    for (const pkg of affectedPackages) {
      const name = pkg.name?.trim();
      if (!name) {
        continue;
      }

      const version = pkg.version?.trim();
      const ecosystem = pkg.ecosystem?.trim();
      const key = `${name}::${version ?? ''}::${ecosystem ?? ''}`;

      if (seen.has(key)) {
        continue;
      }

      seen.add(key);

      components.push({
        name,
        ...(version ? { version } : {}),
        ...(ecosystem ? { ecosystem } : {})
      });
    }

    return components.length > 0 ? components : undefined;
  }

  private buildSummary(findings: readonly RollupFinding[]): string {
    if (findings.length === 0) {
      return 'No findings matched the daily briefing policy for this date.';
    }

    const uniqueProjectPaths = new Set<string>();
    let unmappedCount = 0;

    for (const finding of findings) {
      for (const project of finding.affectedProjects) {
        uniqueProjectPaths.add(project.notePath);
      }

      if (finding.unmappedSboms.length > 0) {
        unmappedCount += 1;
      }
    }

    const criticalCount = findings.filter((finding) =>
      safeInline(finding.vulnerability.severity, 'UNKNOWN').toUpperCase() === 'CRITICAL'
    ).length;

    const highCount = findings.filter((finding) =>
      safeInline(finding.vulnerability.severity, 'UNKNOWN').toUpperCase() === 'HIGH'
    ).length;

    const summaryParts: string[] = [
      `${findings.length} actionable finding${findings.length === 1 ? '' : 's'} matched the rollup policy`,
      `${uniqueProjectPaths.size} mapped project${uniqueProjectPaths.size === 1 ? '' : 's'} were impacted`,
      `${criticalCount} critical and ${highCount} high severit${highCount === 1 ? 'y was' : 'ies were'} identified`
    ];

    if (unmappedCount > 0) {
      summaryParts.push(
        `${unmappedCount} finding${unmappedCount === 1 ? '' : 's'} still require project mapping`
      );
    }

    return asSentence(summaryParts.join('; '));
  }

  private buildFindingRationale(finding: RollupFinding): string {
    const parts: string[] = [
      `Included because severity is ${safeInline(finding.vulnerability.severity, 'Unknown')}`,
      `and triage state is ${formatTriageStateLabel(finding.triageState)}`
    ];

    if (finding.affectedProjects.length > 0) {
      const projects = finding.affectedProjects
        .map((project) => project.displayName.trim())
        .filter((value) => value.length > 0);

      if (projects.length > 0) {
        parts.push(`mapped projects: ${projects.join(', ')}`);
      }
    }

    if (finding.unmappedSboms.length > 0) {
      const unmappedLabels = finding.unmappedSboms
        .map((sbom) => sbom.sbomLabel.trim())
        .filter((value) => value.length > 0);

      if (unmappedLabels.length > 0) {
        parts.push(`unmapped SBOMs: ${unmappedLabels.join(', ')}`);
      }
    }

    if (finding.triageRecord?.reason?.trim()) {
      parts.push(`analyst context: ${truncateInline(asSentence(finding.triageRecord.reason), 160)}`);
    }

    if (finding.triageRecord?.ticketRef?.trim()) {
      parts.push(`ticket: ${finding.triageRecord.ticketRef.trim()}`);
    }

    return asSentence(parts.join('; '));
  }

  private stripLeadingTitleHeading(markdown: string, titleHeading: string): string {
    const normalizedMarkdown = markdown.replace(/\r\n/g, '\n').trim();
    const normalizedTitleHeading = titleHeading.trim();

    if (!normalizedMarkdown.startsWith(normalizedTitleHeading)) {
      return normalizedMarkdown;
    }

    const stripped = normalizedMarkdown.slice(normalizedTitleHeading.length).replace(/^\n+/, '');
    return stripped.trim();
  }

  private sortFindings(findings: readonly RollupFinding[]): RollupFinding[] {
    const severityWeight: Record<string, number> = {
      CRITICAL: 5,
      HIGH: 4,
      MEDIUM: 3,
      LOW: 2,
      INFORMATIONAL: 1,
      UNKNOWN: 0
    };

    return [...findings].sort((left, right) => {
      const leftSeverity = safeInline(left.vulnerability.severity, 'UNKNOWN').toUpperCase();
      const rightSeverity = safeInline(right.vulnerability.severity, 'UNKNOWN').toUpperCase();

      const severityDiff = (severityWeight[rightSeverity] ?? 0) - (severityWeight[leftSeverity] ?? 0);
      if (severityDiff !== 0) {
        return severityDiff;
      }

      const rightCvss = Number.isFinite(right.vulnerability.cvssScore)
        ? right.vulnerability.cvssScore
        : -1;
      const leftCvss = Number.isFinite(left.vulnerability.cvssScore)
        ? left.vulnerability.cvssScore
        : -1;

      if (rightCvss !== leftCvss) {
        return rightCvss - leftCvss;
      }

      return left.vulnerability.id.localeCompare(right.vulnerability.id);
    });
  }
}
