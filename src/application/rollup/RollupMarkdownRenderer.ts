import type { ResolvedAffectedProject } from '../../domain/correlation/AffectedProjectResolution';
import type { RollupFinding } from '../../domain/rollup/RollupFinding';
import { formatTriageStateLabel } from '../../domain/triage/TriageState';
import { WikiLinkFormatter } from '../../infrastructure/obsidian/WikiLinkFormatter';

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

interface ProjectFindingGroup {
  readonly findings: readonly RollupFinding[];
  readonly project: ResolvedAffectedProject;
}

interface MutableProjectFindingGroup {
  findings: RollupFinding[];
  project: ResolvedAffectedProject;
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

const formatCvss = (score: number | null | undefined): string => {
  if (typeof score !== 'number' || !Number.isFinite(score)) {
    return 'N/A';
  }

  return score.toFixed(1);
};

const formatFindingDescriptor = (finding: RollupFinding): string =>
  `**\`${finding.vulnerability.id}\`** | ${safeInline(finding.vulnerability.severity, 'Unknown')} | ${formatTriageStateLabel(finding.triageState)} | CVSS ${formatCvss(finding.vulnerability.cvssScore)}`;

export class RollupMarkdownRenderer {
  public constructor(
    private readonly wikiLinkFormatter = new WikiLinkFormatter()
  ) {}

  public render(input: {
    readonly date: string;
    readonly findings: readonly RollupFinding[];
  }): RenderedDailyRollup {
    const sortedFindings = this.sortFindings(input.findings);
    const projectGroups = this.groupByProject(sortedFindings);
    const unmappedFindings = sortedFindings.filter((finding) => finding.unmappedSboms.length > 0);

    return {
      analystNotesHeading: '## Analyst Notes',
      analystNotesPlaceholder: '- Add analyst notes, escalation context, and follow-up decisions here.',
      managedSections: [
        {
          key: 'executive-summary',
          content: this.renderExecutiveSummary(input.date, sortedFindings, projectGroups, unmappedFindings)
        },
        {
          key: 'affected-projects',
          content: this.renderAffectedProjects(projectGroups)
        },
        {
          key: 'action-items',
          content: this.renderActionItems(projectGroups, unmappedFindings)
        },
        {
          key: 'unmapped-findings',
          content: this.renderUnmappedFindings(unmappedFindings)
        }
      ],
      title: `# VulnDash Briefing ${input.date}`
    };
  }

  private sortFindings(findings: readonly RollupFinding[]): RollupFinding[] {
    const severityWeight: Record<string, number> = {
      'CRITICAL': 5,
      'HIGH': 4,
      'MEDIUM': 3,
      'LOW': 2,
      'INFORMATIONAL': 1,
      'UNKNOWN': 0
    };

    return [...findings].sort((left, right) => {
      const leftSev = safeInline(left.vulnerability.severity, 'UNKNOWN').toUpperCase();
      const rightSev = safeInline(right.vulnerability.severity, 'UNKNOWN').toUpperCase();

      // 1. Sort by Severity Weight (Descending)
      const weightDiff = (severityWeight[rightSev] ?? 0) - (severityWeight[leftSev] ?? 0);
      if (weightDiff !== 0) {
        return weightDiff;
      }

      // 2. Sort by CVSS Score (Descending)
      const rightCvss = right.vulnerability.cvssScore ?? -1;
      const leftCvss = left.vulnerability.cvssScore ?? -1;
      if (rightCvss !== leftCvss) {
        return rightCvss - leftCvss;
      }

      // 3. Fallback to ID (Ascending)
      return left.vulnerability.id.localeCompare(right.vulnerability.id);
    });
  }

  private groupByProject(findings: readonly RollupFinding[]): ProjectFindingGroup[] {
    const groups = new Map<string, MutableProjectFindingGroup>();

    for (const finding of findings) {
      for (const project of finding.affectedProjects) {
        const existing = groups.get(project.notePath);

        if (existing) {
          if (!existing.findings.some((entry) => entry.vulnerability.id === finding.vulnerability.id)) {
            existing.findings.push(finding);
          }
          continue;
        }

        groups.set(project.notePath, {
          findings: [finding],
          project
        });
      }
    }

    return Array.from(groups.values())
      .map((group) => ({
        project: group.project,
        findings: this.sortFindings(group.findings)
      }))
      .sort((left, right) =>
        left.project.displayName.localeCompare(right.project.displayName)
        || left.project.notePath.localeCompare(right.project.notePath));
  }

  private renderExecutiveSummary(
    date: string,
    findings: readonly RollupFinding[],
    projectGroups: readonly ProjectFindingGroup[],
    unmappedFindings: readonly RollupFinding[]
  ): string {
    if (findings.length === 0) {
      return [
        '## Executive Summary',
        '',
        '> [!success] All Clear',
        `> No findings matched the daily briefing policy for ${date}.`,
        '> ',
        '> Existing analyst notes remain below for continuity.'
      ].join('\n');
    }

    const uniqueProjects = projectGroups.map((group) =>
      this.wikiLinkFormatter.format(group.project.notePath, group.project.displayName));

    const severityCounts = new Map<string, number>();
    for (const finding of findings) {
      const severity = safeInline(finding.vulnerability.severity, 'Unknown');
      severityCounts.set(severity, (severityCounts.get(severity) ?? 0) + 1);
    }

    const severityWeight: Record<string, number> = {
      'CRITICAL': 5, 'HIGH': 4, 'MEDIUM': 3, 'LOW': 2, 'INFORMATIONAL': 1, 'UNKNOWN': 0
    };

    const severitySummary = Array.from(severityCounts.entries())
      .sort((left, right) => (severityWeight[right[0].toUpperCase()] ?? 0) - (severityWeight[left[0].toUpperCase()] ?? 0))
      .map(([severity, count]) => `**${count}** ${severity}`)
      .join(', ');

    return [
      '## Executive Summary',
      '',
      '> [!summary] Threat Intelligence Snapshot',
      `> - **Total Findings:** ${findings.length} actionable finding${findings.length === 1 ? '' : 's'} matched the policy.`,
      `> - **Severity Mix:** ${severitySummary}.`,
      uniqueProjects.length > 0
        ? `> - **Impacted Projects:** ${uniqueProjects.length} mapped project${uniqueProjects.length === 1 ? '' : 's'} require review.`
        : '> - **Impacted Projects:** No mapped project notes were resolved.',
      unmappedFindings.length > 0
        ? `> - **Pending Triage:** ${unmappedFindings.length} finding${unmappedFindings.length === 1 ? '' : 's'} need project mapping.`
        : '> - **Pending Triage:** None.'
    ].join('\n');
  }

  private renderAffectedProjects(projectGroups: readonly ProjectFindingGroup[]): string {
    if (projectGroups.length === 0) {
      return [
        '## Affected Projects',
        '',
        '- *No mapped project findings matched the current rollup policy.*'
      ].join('\n');
    }

    const lines: string[] = ['## Affected Projects', ''];

    for (const group of projectGroups) {
      lines.push(`### ${this.wikiLinkFormatter.format(group.project.notePath, group.project.displayName)}`);
      lines.push('');

      for (const finding of group.findings) {
        lines.push(`- ${formatFindingDescriptor(finding)}`);
        lines.push(`  - **Title:** ${safeInline(finding.vulnerability.title)}`);

        const summary = asSentence(truncateInline(safeInline(finding.vulnerability.summary, 'No summary provided')));
        lines.push(`  - **Summary:** ${summary}`);

        const sourceSboms = group.project.sourceSbomLabels.length > 0
          ? group.project.sourceSbomLabels.join(', ')
          : 'None linked';
        lines.push(`  - **Source SBOMs:** ${sourceSboms}`);

        if (finding.triageRecord?.ticketRef?.trim()) {
          lines.push(`  - **Ticket:** ${finding.triageRecord.ticketRef.trim()}`);
        }

        if (finding.triageRecord?.reason?.trim()) {
          lines.push(`  - **Analyst Context:** ${asSentence(truncateInline(finding.triageRecord.reason, 140))}`);
        }

        lines.push('');
      }
    }

    return lines.join('\n').trimEnd();
  }

  private renderActionItems(
    projectGroups: readonly ProjectFindingGroup[],
    unmappedFindings: readonly RollupFinding[]
  ): string {
    const tasks: string[] = ['## Action Items', '', '> [!todo] Required Reviews'];

    for (const group of projectGroups) {
      const projectLink = this.wikiLinkFormatter.format(group.project.notePath, group.project.displayName);

      for (const finding of group.findings) {
        tasks.push(
          `> - [ ] Assess **${finding.vulnerability.id}** (${safeInline(finding.vulnerability.severity, 'Unknown')}, ${formatTriageStateLabel(finding.triageState)}) for ${projectLink}`
        );
      }
    }

    for (const finding of unmappedFindings) {
      const unmappedLabels = finding.unmappedSboms.map((sbom) => sbom.sbomLabel).join(', ');
      tasks.push(
        `> - [ ] Map **${finding.vulnerability.id}** to an internal project note (Source: *${unmappedLabels || 'Unknown SBOM'}*)`
      );
    }

    if (tasks.length === 3) {
      tasks.push('> - [x] No action items required today.');
    }

    return tasks.join('\n');
  }

  private renderUnmappedFindings(findings: readonly RollupFinding[]): string {
    if (findings.length === 0) {
      return [
        '## Unmapped Findings',
        '',
        '- *No unmapped findings matched the current rollup policy.*'
      ].join('\n');
    }

    const lines: string[] = ['## Unmapped Findings', ''];

    for (const finding of findings) {
      const labels = finding.unmappedSboms.map((sbom) => sbom.sbomLabel).join(', ');

      lines.push(`- ${formatFindingDescriptor(finding)}`);
      lines.push(`  - **Title:** ${safeInline(finding.vulnerability.title)}`);
      lines.push(`  - **Summary:** ${asSentence(truncateInline(safeInline(finding.vulnerability.summary, 'No summary provided')))}`);
      lines.push(`  - **Unmapped SBOMs:** ${labels || 'Unknown SBOM'}`);
      lines.push('');
    }

    return lines.join('\n').trimEnd();
  }
}
