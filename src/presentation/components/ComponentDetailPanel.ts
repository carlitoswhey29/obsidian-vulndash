import { App, Component, MarkdownRenderer, normalizePath } from 'obsidian';
import type { RelatedVulnerabilitySummary, TrackedComponent } from '../../application/sbom/types';
import { sanitizeText, sanitizeUrl } from '../../infrastructure/security/sanitize';

export interface ComponentDetailPanelCallbacks {
  effectiveHighestSeverity?: string;
  onOpenNote?: (notePath: string) => void;
  relatedVulnerabilities?: readonly RelatedVulnerabilitySummary[];
}

interface RenderableRelatedVulnerability {
  id: string;
  severity?: string | undefined;
  score?: number | undefined;
  source?: string | undefined;
  summary?: string | undefined;
  refs?: string | undefined;
  evidence?: string | undefined;
  notePath?: string | undefined;
}

interface RenderableEmbeddedVulnerability {
  id: string;
  severity?: string | undefined;
  score?: number | undefined;
  source?: string | undefined;
  summary?: string | undefined;
  sourceUrl?: string | undefined;
}

type RenderableVulnerability = RenderableRelatedVulnerability | RenderableEmbeddedVulnerability;

const formatSeverity = (severity: string | undefined): string => {
  const safeSeverity = sanitizeText(severity ?? '').trim();
  return safeSeverity
    ? `${safeSeverity.charAt(0).toUpperCase()}${safeSeverity.slice(1)}`
    : 'None';
};

const formatList = (values: readonly string[]): string => {
  const safeValues = values
    .map((value) => sanitizeText(value).trim())
    .filter((value) => value.length > 0);

  return safeValues.length > 0 ? safeValues.join(', ') : 'None';
};

export class ComponentDetailsRenderer extends Component {
  private readonly renderComponentsByContainer = new WeakMap<HTMLElement, Component>();

  public constructor(
    private readonly app: App,
    private readonly sourcePath: string
  ) {
    super();
  }

  public async renderDetails(
    containerEl: HTMLElement,
    component: TrackedComponent,
    callbacks: ComponentDetailPanelCallbacks = {}
  ): Promise<void> {
    this.renderComponentsByContainer.get(containerEl)?.unload();
    containerEl.empty();
    containerEl.addClass('vulndash-component-details');

    const markdown = this.buildMarkdown(component, callbacks);
    const renderComponent = new Component();
    this.addChild(renderComponent);
    this.renderComponentsByContainer.set(containerEl, renderComponent);

    try {
      await MarkdownRenderer.render(
        this.app,
        markdown,
        containerEl,
        this.getSafeSourcePath(),
        renderComponent
      );
    } finally {
      if (this.renderComponentsByContainer.get(containerEl) !== renderComponent) {
        renderComponent.unload();
      }
    }
  }

  private buildMarkdown(
    component: TrackedComponent,
    callbacks: ComponentDetailPanelCallbacks
  ): string {
    const relatedVulnerabilities = Array.isArray(callbacks.relatedVulnerabilities)
      ? callbacks.relatedVulnerabilities
      : [];

    const embeddedVulnerabilities = Array.isArray(component.vulnerabilities)
      ? component.vulnerabilities
      : [];

    const relatedIds = new Set(
      relatedVulnerabilities
        .map((vulnerability) => this.normalizeComparableId(vulnerability.id))
        .filter((id) => id.length > 0)
    );

    const embeddedOnlyVulnerabilities = embeddedVulnerabilities.filter((vulnerability) => {
      const normalizedId = this.normalizeComparableId(vulnerability.id);
      return normalizedId.length === 0 || !relatedIds.has(normalizedId);
    });

    const totalVulns = relatedVulnerabilities.length + embeddedOnlyVulnerabilities.length;
    const severity = formatSeverity(
      callbacks.effectiveHighestSeverity ?? component.highestSeverity
    );

    const headerLines: string[] = [
      `## ${this.escapeMd(this.toSafeText(component.key, 'Unknown Component'))}`,
      '',
      `- **Supplier:** ${this.escapeMd(this.toSafeText(component.supplier, 'Unknown'))}`,
      `- **License:** ${this.escapeMd(this.toSafeText(component.license, 'Unknown'))}`,
      `- **Formats:** ${this.escapeMd(formatList(this.toStringArray(component.formats)))}`,
      `- **PURL:** \`${this.escapeInlineCode(this.toSafeText(component.purl, 'None'))}\``,
      `- **CPE:** \`${this.escapeInlineCode(this.toSafeText(component.cpe, 'None'))}\``,
      `- **Source Files:** ${this.renderInlineCodeList(this.toStringArray(component.sourceFiles))}`,
      `- **Highest Severity:** ${this.escapeMd(severity)}`,
      `- **Vulnerabilities:** ${totalVulns}`
    ];

    const safeComponentNoteLink = this.toSafeWikiLink(component.notePath);
    if (safeComponentNoteLink) {
      headerLines.push(`- **Linked Note:** ${safeComponentNoteLink}`);
    }

    headerLines.push('');

    const cweGroups = Array.isArray(component.cweGroups) ? component.cweGroups : [];
    if (cweGroups.length > 0) {
      const cwes = cweGroups
        .map((group) => {
          // Explicit nullish check ensures numeric '0' is safely cast and retained
          const cweValue = group.cwe != null ? this.toSafeText(String(group.cwe), '').trim() : '';
          const countValue = this.toNonNegativeInteger(group.count);
          return cweValue ? `CWE-${cweValue} (${countValue})` : '';
        })
        .filter((value) => value.length > 0)
        .join(', ');

      if (cwes) {
        headerLines.push(`**CWE Groups:** ${this.escapeMd(cwes)}`);
        headerLines.push('');
      }
    }

    const summaryCallout =
      totalVulns > 0
        ? [
            `> [!danger] Vulnerability Summary`,
            `> This component is associated with **${totalVulns}** vulnerabilit${totalVulns === 1 ? 'y' : 'ies'}.`,
            ''
          ].join('\n')
        : [
            `> [!success] Status`,
            `> No vulnerabilities are currently associated with this component.`,
            ''
          ].join('\n');

    let vulnSections = '';
    if (totalVulns > 0) {
      vulnSections += `### Affected Vulnerabilities\n\n`;

      const relatedToRender: RenderableRelatedVulnerability[] = relatedVulnerabilities
        .slice(0, 10)
        .map((vulnerability) => ({
          id: this.toSafeText(vulnerability.id, 'Unknown Vulnerability'),
          severity: formatSeverity(vulnerability.severity),
          score: this.toFiniteNumberOrUndefined(vulnerability.cvssScore),
          source: this.toSafeText(vulnerability.source, ''),
          summary: this.toSafeText(vulnerability.title, ''),
          refs: `${this.toNonNegativeInteger(vulnerability.referenceCount)} reference${vulnerability.referenceCount === 1 ? '' : 's'}`,
          evidence: this.toSafeText(vulnerability.evidence, ''),
          notePath: this.toSafeText(vulnerability.notePath, '')
        }));

      const embeddedToRender: RenderableEmbeddedVulnerability[] = embeddedOnlyVulnerabilities
        .slice(0, 10)
        .map((vulnerability) => ({
          id: this.toSafeText(vulnerability.id, 'Unknown Vulnerability'),
          severity: formatSeverity(vulnerability.severity),
          score: this.toFiniteNumberOrUndefined(vulnerability.score),
          source: this.toSafeText(vulnerability.sourceName, ''),
          summary: this.toSafeText(vulnerability.description, ''),
          sourceUrl: this.toSafeText(vulnerability.sourceUrl, '')
        }));

      const allVulnsToRender: RenderableVulnerability[] = [
        ...relatedToRender,
        ...embeddedToRender
      ];

      vulnSections += allVulnsToRender
        .map((vulnerability) => this.renderVulnerabilitySection(vulnerability))
        .join('\n');

      const hiddenCount =
        Math.max(relatedVulnerabilities.length - 10, 0) +
        Math.max(embeddedOnlyVulnerabilities.length - 10, 0);

      if (hiddenCount > 0) {
        vulnSections += `\n_${hiddenCount} additional vulnerabilities are hidden in this summary._\n\n`;
      }
    } else {
      vulnSections += `### Affected Vulnerabilities\n\n_None._\n\n`;
    }

    let sourceRecords = `### Source Records\n\n`;
    const sources = Array.isArray(component.sources) ? component.sources : [];
    if (sources.length > 0) {
      sourceRecords += sources
        .map((source) => {
          const documentName = this.escapeMd(
            this.toSafeText(source.documentName, 'Unknown Document')
          );

          const format =
            source.format === 'cyclonedx'
              ? 'CycloneDX'
              : source.format === 'spdx'
                ? 'SPDX'
                : this.toSafeText(source.format, 'Unknown');

          const safeVersion = this.toSafeText(source.version, '').trim();
          const versionStr = safeVersion
            ? `, v${this.escapeMd(safeVersion)}`
            : '';

          const safePath = this.escapeInlineCode(
            this.toSafeText(source.sourcePath, 'Unknown Path')
          );

          return `- **${documentName}** (${this.escapeMd(format)}${versionStr})\n  - Path: \`${safePath}\``;
        })
        .join('\n\n');
    } else {
      sourceRecords += '_No source records available._';
    }

    return [headerLines.join('\n'), summaryCallout, vulnSections, sourceRecords].join('\n');
  }

  private renderVulnerabilitySection(vulnerability: RenderableVulnerability): string {
    const lines: string[] = [
      `#### ${this.escapeMd(this.toSafeText(vulnerability.id, 'Unknown Vulnerability'))}`,
      '',
      `- **Severity:** ${this.escapeMd(this.toSafeText(vulnerability.severity, 'Unknown'))}`
    ];

    const safeScore = this.toFiniteNumberOrUndefined(vulnerability.score);
    if (safeScore !== undefined) {
      lines.push(`- **Score:** ${safeScore.toFixed(1)}`);
    }

    if (vulnerability.source) {
      lines.push(`- **Source:** ${this.escapeMd(this.toSafeText(vulnerability.source, ''))}`);
    }

    if ('refs' in vulnerability && vulnerability.refs) {
      lines.push(`- **References:** ${this.escapeMd(this.toSafeText(vulnerability.refs, ''))}`);
    }

    if ('evidence' in vulnerability && vulnerability.evidence) {
      lines.push(`- **Evidence:** ${this.escapeMd(this.toSafeText(vulnerability.evidence, ''))}`);
    }

    if ('notePath' in vulnerability && vulnerability.notePath) {
      const safeLink = this.toSafeWikiLink(vulnerability.notePath);
      if (safeLink) {
        lines.push(`- **Linked Note:** ${safeLink}`);
      }
    }

    if ('sourceUrl' in vulnerability && vulnerability.sourceUrl) {
      const safeUrl = sanitizeUrl(vulnerability.sourceUrl);
      if (safeUrl) {
        lines.push(`- **Advisory:** [Open Source](${safeUrl})`);
      }
    }

    lines.push('');
    lines.push(
      vulnerability.summary
        ? this.escapeMd(this.toSafeText(vulnerability.summary, ''))
        : '_No description available._'
    );
    lines.push('');
    lines.push('---');
    lines.push('');

    return lines.join('\n');
  }

  private renderInlineCodeList(values: readonly string[]): string {
    const safeValues = values
      .map((value) => this.toSafeText(value, '').trim())
      .filter((value) => value.length > 0)
      .map((value) => `\`${this.escapeInlineCode(value)}\``);

    return safeValues.length > 0 ? safeValues.join(', ') : 'None';
  }

  private toSafeWikiLink(notePath: string | null | undefined): string | undefined {
    const safePath = this.sanitizeInternalLinkTarget(notePath);
    return safePath ? `[[${safePath}]]` : undefined;
  }

  private sanitizeInternalLinkTarget(value: string | null | undefined): string | undefined {
    const sanitized = sanitizeText(value ?? '')
      .replace(/[\r\n\t]/g, ' ')
      .replace(/\[|\]|\|/g, ' ')
      .replace(/#{2,}/g, '#')
      .replace(/\^{2,}/g, '^')
      .trim();

    if (!sanitized) {
      return undefined;
    }

    const normalized = normalizePath(sanitized)
      .replace(/\[|\]|\|/g, ' ')
      .replace(/\.md$/i, '')
      .trim();

    return normalized || undefined;
  }

  private normalizeComparableId(value: string | undefined): string {
    return sanitizeText(value ?? '').trim().toLowerCase();
  }

  private toStringArray(value: readonly string[] | undefined): string[] {
    return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
  }

  private toSafeText(value: string | null | undefined, fallback: string): string {
    const sanitized = sanitizeText(value ?? '').trim();
    return sanitized || fallback;
  }

  private toFiniteNumberOrUndefined(value: unknown): number | undefined {
    return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
  }

  private toNonNegativeInteger(value: unknown): number {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      return 0;
    }

    return Math.max(0, Math.trunc(value));
  }

  private getSafeSourcePath(): string {
    const sanitized = sanitizeText(this.sourcePath ?? '').trim();
    return sanitized ? normalizePath(sanitized) : '';
  }

  private escapeMd(value: string): string {
    return value.replace(/[\\`*_{}[\]()#+!|>]/g, '\\$&');
  }

  private escapeInlineCode(value: string): string {
    return value.replace(/`/g, '\\`');
  }
}
