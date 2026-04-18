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
  readonly findings: RollupFinding[];
  readonly project: ResolvedAffectedProject;
}

const asSentence = (value: string): string =>
  value.endsWith('.') ? value : `${value}.`;

const truncateInline = (value: string, maxLength = 180): string => {
  const normalized = value.replace(/\s+/g, ' ').trim();
  if (normalized.length <= maxLength) {
    return normalized;
  }

  return `${normalized.slice(0, maxLength - 1).trimEnd()}…`;
};

const formatFindingDescriptor = (finding: RollupFinding): string =>
  `\`${finding.vulnerability.id}\` ${finding.vulnerability.severity} · ${formatTriageStateLabel(finding.triageState)} · CVSS ${finding.vulnerability.cvssScore.toFixed(1)}`;

export class RollupMarkdownRenderer {
  public constructor(
    private readonly wikiLinkFormatter = new WikiLinkFormatter()
  ) {}

  public render(input: {
    readonly date: string;
    readonly findings: readonly RollupFinding[];
  }): RenderedDailyRollup {
    const projectGroups = this.groupByProject(input.findings);
    const unmappedFindings = input.findings.filter((finding) => finding.unmappedSboms.length > 0);

    return {
      analystNotesHeading: '## Analyst Notes',
      analystNotesPlaceholder: '- Add analyst notes, escalation context, and follow-up decisions here.',
      managedSections: [
        {
          key: 'executive-summary',
          content: this.renderExecutiveSummary(input.date, input.findings, projectGroups, unmappedFindings)
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

  private groupByProject(findings: readonly RollupFinding[]): ProjectFindingGroup[] {
    const groups = new Map<string, ProjectFindingGroup>();

    for (const finding of findings) {
      for (const project of finding.affectedProjects) {
        const existing = groups.get(project.notePath);
        if (existing) {
          existing.findings.push(finding);
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
        ...group,
        findings: [...group.findings]
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
        `- No findings matched the daily briefing policy for ${date}.`,
        '- Existing analyst notes remain below for continuity.'
      ].join('\n');
    }

    const uniqueProjects = projectGroups.map((group) =>
      this.wikiLinkFormatter.format(group.project.notePath, group.project.displayName));
    const severityCounts = new Map<string, number>();
    for (const finding of findings) {
      severityCounts.set(finding.vulnerability.severity, (severityCounts.get(finding.vulnerability.severity) ?? 0) + 1);
    }

    const severitySummary = Array.from(severityCounts.entries())
      .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
      .map(([severity, count]) => `${count} ${severity}`)
      .join(', ');

    return [
      '## Executive Summary',
      '',
      `- ${findings.length} actionable finding${findings.length === 1 ? '' : 's'} matched the daily briefing policy for ${date}.`,
      uniqueProjects.length > 0
        ? `- ${uniqueProjects.length} mapped project${uniqueProjects.length === 1 ? '' : 's'} require review: ${uniqueProjects.join(', ')}.`
        : '- No mapped project notes were resolved for the selected findings.',
      `- Severity mix: ${severitySummary}.`,
      unmappedFindings.length > 0
        ? `- ${unmappedFindings.length} finding${unmappedFindings.length === 1 ? '' : 's'} still need project mapping triage.`
        : '- No unmapped findings are pending project-note correlation.'
    ].join('\n');
  }

  private renderAffectedProjects(projectGroups: readonly ProjectFindingGroup[]): string {
    if (projectGroups.length === 0) {
      return [
        '## Affected Projects',
        '',
        '- No mapped project findings matched the current rollup policy.'
      ].join('\n');
    }

    const lines = ['## Affected Projects', ''];
    for (const group of projectGroups) {
      lines.push(`### ${this.wikiLinkFormatter.format(group.project.notePath, group.project.displayName)}`);
      lines.push('');

      for (const finding of group.findings) {
        lines.push(`- ${formatFindingDescriptor(finding)}`);
        lines.push(`- Title: ${finding.vulnerability.title}`);
        lines.push(`- Summary: ${asSentence(truncateInline(finding.vulnerability.summary))}`);
        lines.push(`- Source SBOMs: ${group.project.sourceSbomLabels.join(', ') || 'None linked'}`);
        if (finding.triageRecord?.ticketRef) {
          lines.push(`- Ticket: ${finding.triageRecord.ticketRef}`);
        }
        if (finding.triageRecord?.reason) {
          lines.push(`- Analyst context: ${asSentence(truncateInline(finding.triageRecord.reason, 140))}`);
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
    const tasks = ['## Action Items', ''];

    for (const group of projectGroups) {
      const projectLink = this.wikiLinkFormatter.format(group.project.notePath, group.project.displayName);
      for (const finding of group.findings) {
        tasks.push(`- [ ] ${projectLink} assess ${finding.vulnerability.id} (${finding.vulnerability.severity}, ${formatTriageStateLabel(finding.triageState)}).`);
      }
    }

    for (const finding of unmappedFindings) {
      const unmappedLabels = finding.unmappedSboms.map((sbom) => sbom.sbomLabel).join(', ');
      tasks.push(`- [ ] Map ${finding.vulnerability.id} to an internal project note for: ${unmappedLabels}.`);
    }

    if (tasks.length === 2) {
      tasks.push('- No action items were generated from the current policy output.');
    }

    return tasks.join('\n');
  }

  private renderUnmappedFindings(findings: readonly RollupFinding[]): string {
    if (findings.length === 0) {
      return [
        '## Unmapped Findings',
        '',
        '- No unmapped findings matched the current rollup policy.'
      ].join('\n');
    }

    const lines = ['## Unmapped Findings', ''];
    for (const finding of findings) {
      const labels = finding.unmappedSboms.map((sbom) => sbom.sbomLabel).join(', ');
      lines.push(`- ${formatFindingDescriptor(finding)} · Unmapped SBOMs: ${labels}`);
      lines.push(`- Title: ${finding.vulnerability.title}`);
      lines.push(`- Summary: ${asSentence(truncateInline(finding.vulnerability.summary))}`);
      lines.push('');
    }

    return lines.join('\n').trimEnd();
  }
}
