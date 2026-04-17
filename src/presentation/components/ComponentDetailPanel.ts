import type { RelatedVulnerabilitySummary, TrackedComponent } from '../../application/sbom/types';
import { sanitizeText, sanitizeUrl } from '../../infrastructure/security/sanitize';

export interface ComponentDetailPanelCallbacks {
  effectiveHighestSeverity?: string;
  onOpenNote?: (notePath: string) => void;
  relatedVulnerabilities?: readonly RelatedVulnerabilitySummary[];
}

const formatSeverity = (severity: string | undefined): string =>
  severity ? `${severity.charAt(0).toUpperCase()}${severity.slice(1)}` : 'None';

const formatList = (values: readonly string[]): string =>
  values.length > 0 ? values.join(', ') : 'None';

const renderField = (
  containerEl: HTMLElement,
  label: string,
  value: string,
  options?: {
    mono?: boolean;
    multiline?: boolean;
  }
): void => {
  const field = containerEl.createDiv({ cls: 'vulndash-component-detail-field' });
  field.createDiv({ cls: 'vulndash-component-detail-label', text: label });
  field.createDiv({
    cls: `vulndash-component-detail-value${options?.mono ? ' is-mono' : ''}${options?.multiline ? ' is-multiline' : ''}`,
    text: value
  });
};

export const renderComponentDetailPanel = (
  containerEl: HTMLElement,
  component: TrackedComponent,
  callbacks: ComponentDetailPanelCallbacks = {}
): void => {
  containerEl.empty();
  containerEl.addClass('vulndash-component-detail-panel');

  const summaryGrid = containerEl.createDiv({ cls: 'vulndash-component-detail-grid' });
  renderField(summaryGrid, 'Component Key', component.key, { mono: true, multiline: true });
  renderField(summaryGrid, 'Formats', formatList(component.formats));
  renderField(summaryGrid, 'Source Files', formatList(component.sourceFiles), { multiline: true });
  renderField(summaryGrid, 'Supplier', component.supplier ?? 'Unknown');
  renderField(summaryGrid, 'License', component.license ?? 'Unknown');
  renderField(summaryGrid, 'PURL', component.purl ?? 'None', { mono: true, multiline: true });
  renderField(summaryGrid, 'CPE', component.cpe ?? 'None', { mono: true, multiline: true });
  renderField(summaryGrid, 'Highest Severity', formatSeverity(callbacks.effectiveHighestSeverity ?? component.highestSeverity));

  const cweSection = containerEl.createDiv({ cls: 'vulndash-component-detail-section' });
  cweSection.createEl('h4', { text: 'CWE Groups' });
  if (component.cweGroups.length === 0) {
    cweSection.createEl('p', { cls: 'vulndash-muted-copy', text: 'No CWE group data is available for this component.' });
  } else {
    const cweList = cweSection.createDiv({ cls: 'vulndash-component-chip-list' });
    for (const group of component.cweGroups) {
      cweList.createSpan({
        cls: 'vulndash-badge vulndash-badge-neutral',
        text: `CWE-${group.cwe} (${group.count})`
      });
    }
  }

  const vulnerabilitySection = containerEl.createDiv({ cls: 'vulndash-component-detail-section' });
  vulnerabilitySection.createEl('h4', { text: 'Vulnerability Summary' });
  const relatedVulnerabilities = callbacks.relatedVulnerabilities ?? [];
  const relatedIds = new Set(relatedVulnerabilities.map((vulnerability) => vulnerability.id.trim().toLowerCase()));
  const embeddedOnlyVulnerabilities = component.vulnerabilities.filter((vulnerability) =>
    !relatedIds.has(vulnerability.id.trim().toLowerCase())
  );

  if (relatedVulnerabilities.length === 0 && embeddedOnlyVulnerabilities.length === 0) {
    vulnerabilitySection.createEl('p', { cls: 'vulndash-muted-copy', text: 'No vulnerability data is present for this component.' });
  } else {
    const vulnerabilityList = vulnerabilitySection.createDiv({ cls: 'vulndash-component-vulnerability-list' });
    for (const vulnerability of relatedVulnerabilities.slice(0, 10)) {
      const item = vulnerabilityList.createDiv({ cls: 'vulndash-component-vulnerability-item' });
      const header = item.createDiv({ cls: 'vulndash-component-vulnerability-header' });
      header.createSpan({ cls: 'vulndash-component-vulnerability-id', text: sanitizeText(vulnerability.id) });
      header.createSpan({
        cls: `vulndash-severity-pill is-${vulnerability.severity.toLowerCase()}`,
        text: vulnerability.severity
      });

      const meta = item.createDiv({ cls: 'vulndash-muted-copy' });
      meta.setText([
        vulnerability.source,
        `CVSS ${vulnerability.cvssScore.toFixed(1)}`,
        `${vulnerability.referenceCount} reference${vulnerability.referenceCount === 1 ? '' : 's'}`,
        vulnerability.evidence
      ].join(' • '));
      item.createEl('p', {
        cls: 'vulndash-component-vulnerability-description',
        text: sanitizeText(vulnerability.title)
      });

      if (vulnerability.notePath && callbacks.onOpenNote) {
        const noteButton = item.createEl('button', { text: 'Open Note' });
        noteButton.addEventListener('click', () => {
          callbacks.onOpenNote?.(vulnerability.notePath!);
        });
      }
    }

    for (const vulnerability of embeddedOnlyVulnerabilities.slice(0, 10)) {
      const item = vulnerabilityList.createDiv({ cls: 'vulndash-component-vulnerability-item' });
      const header = item.createDiv({ cls: 'vulndash-component-vulnerability-header' });
      header.createSpan({ cls: 'vulndash-component-vulnerability-id', text: sanitizeText(vulnerability.id) });
      header.createSpan({
        cls: `vulndash-severity-pill is-${vulnerability.severity ?? 'none'}`,
        text: formatSeverity(vulnerability.severity)
      });

      const meta = item.createDiv({ cls: 'vulndash-muted-copy' });
      meta.setText([
        vulnerability.score !== undefined ? `Score ${vulnerability.score.toFixed(1)}` : '',
        vulnerability.cwes.length > 0 ? vulnerability.cwes.map((cwe) => `CWE-${cwe}`).join(', ') : '',
        vulnerability.sourceName ?? ''
      ].filter(Boolean).join(' • '));

      if (vulnerability.description) {
        item.createEl('p', {
          cls: 'vulndash-component-vulnerability-description',
          text: sanitizeText(vulnerability.description)
        });
      }

      const safeSourceUrl = vulnerability.sourceUrl ? sanitizeUrl(vulnerability.sourceUrl) : '';
      if (safeSourceUrl) {
        const link = item.createEl('a', {
          text: 'Open advisory source'
        });
        link.href = safeSourceUrl;
        link.rel = 'noopener noreferrer';
        link.target = '_blank';
      }
    }

    const hiddenCount = Math.max(relatedVulnerabilities.length - 10, 0) + Math.max(embeddedOnlyVulnerabilities.length - 10, 0);
    if (hiddenCount > 0) {
      vulnerabilitySection.createEl('p', {
        cls: 'vulndash-muted-copy',
        text: `${hiddenCount} additional vulnerabilities are hidden in this summary.`
      });
    }
  }

  const sourceSection = containerEl.createDiv({ cls: 'vulndash-component-detail-section' });
  sourceSection.createEl('h4', { text: 'Source Records' });
  const sourceList = sourceSection.createDiv({ cls: 'vulndash-component-source-list' });
  for (const source of component.sources) {
    const item = sourceList.createDiv({ cls: 'vulndash-component-source-item' });
    item.createDiv({ cls: 'vulndash-component-source-title', text: sanitizeText(source.documentName) });
    item.createDiv({
      cls: 'vulndash-muted-copy',
      text: [
        source.format === 'cyclonedx' ? 'CycloneDX' : 'SPDX',
        source.version ?? '',
        source.sourcePath
      ].filter(Boolean).join(' • ')
    });
  }

  if (component.notePath) {
    const noteSection = containerEl.createDiv({ cls: 'vulndash-component-detail-section' });
    noteSection.createEl('h4', { text: 'Linked Note' });
    renderField(noteSection, 'Note Path', component.notePath, { mono: true, multiline: true });

    if (callbacks.onOpenNote) {
      const openButton = noteSection.createEl('button', { text: 'Open Note' });
      openButton.addEventListener('click', () => {
        callbacks.onOpenNote?.(component.notePath!);
      });
    }
  }
};
