import { Modal } from 'obsidian';
import type { SbomComparisonGroup, SbomComparisonResult } from '../../application/services/SbomComparisonService';
import type VulnDashPlugin from '../../plugin';

export class SbomCompareModal extends Modal {
  private rightSbomId = '';

  public constructor(
    private readonly plugin: VulnDashPlugin,
    private readonly leftSbomId: string
  ) {
    super(plugin.app);
    const candidates = this.getComparisonCandidates();
    this.rightSbomId = candidates[0]?.id ?? '';
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-sbom-compare-modal');
    this.render();
  }

  private render(): void {
    const { contentEl } = this;
    contentEl.empty();

    const leftSbom = this.plugin.getSbomById(this.leftSbomId);
    if (!leftSbom) {
      contentEl.createEl('p', { text: 'Primary SBOM entry was not found.' });
      return;
    }

    contentEl.createEl('h2', { text: `Compare ${leftSbom.label}` });
    const candidates = this.getComparisonCandidates();
    if (candidates.length === 0) {
      contentEl.createEl('p', { text: 'Add at least one more SBOM to compare.' });
      return;
    }

    const picker = contentEl.createDiv({ cls: 'vulndash-sbom-compare-picker' });
    picker.createEl('label', { text: 'Compare against' });
    const select = picker.createEl('select');
    for (const candidate of candidates) {
      const option = select.createEl('option', {
        text: candidate.label
      });
      option.value = candidate.id;
      option.selected = candidate.id === this.rightSbomId;
    }
    select.addEventListener('change', () => {
      this.rightSbomId = select.value;
      this.render();
    });

    const comparison = this.plugin.compareSboms(this.leftSbomId, this.rightSbomId);
    if (!comparison) {
      contentEl.createEl('p', { text: 'Unable to build comparison for the selected SBOMs.' });
      return;
    }

    const rightSbom = this.plugin.getSbomById(this.rightSbomId);
    if (!rightSbom) {
      return;
    }

    contentEl.createEl('p', {
      text: [
        `${leftSbom.label} vs ${rightSbom.label}`,
        `${comparison.changed.length} changed group${comparison.changed.length === 1 ? '' : 's'}`,
        `${comparison.leftOnly.length} left-only`,
        `${comparison.rightOnly.length} right-only`,
        `${comparison.unchangedCount} unchanged`
      ].join(' | ')
    });

    this.renderGroupSection(contentEl, 'Changed', comparison, 'changed');
    this.renderGroupSection(contentEl, `Only in ${leftSbom.label}`, comparison, 'leftOnly');
    this.renderGroupSection(contentEl, `Only in ${rightSbom.label}`, comparison, 'rightOnly');
  }

  private renderGroupSection(
    container: HTMLElement,
    heading: string,
    comparison: SbomComparisonResult,
    key: 'changed' | 'leftOnly' | 'rightOnly'
  ): void {
    const entries = comparison[key];
    container.createEl('h3', { text: heading });
    if (entries.length === 0) {
      container.createEl('p', { text: 'None.' });
      return;
    }

    const list = container.createEl('ul');
    if (key === 'changed') {
      for (const change of comparison.changed) {
        const item = list.createEl('li');
        item.createEl('strong', { text: change.label });
        item.createSpan({ text: ` | Fields: ${change.fields.join(', ') || 'unspecified'}` });
        item.createEl('div', { text: `Left: ${this.summarizeGroup(change.left)}` });
        item.createEl('div', { text: `Right: ${this.summarizeGroup(change.right)}` });
      }
      return;
    }

    for (const group of entries as SbomComparisonGroup[]) {
      const item = list.createEl('li');
      item.createEl('strong', { text: group.label });
      item.createSpan({ text: ` | ${this.summarizeGroup(group.components)}` });
    }
  }

  private summarizeGroup(components: Array<{ name: string; normalizedName: string; version: string }>): string {
    return components
      .map((component) => `${component.normalizedName || component.name}${component.version ? ` ${component.version}` : ''}`)
      .join(', ');
  }

  private getComparisonCandidates(): Array<{ id: string; label: string }> {
    return this.plugin.getSettings().sboms
      .filter((sbom) => sbom.id !== this.leftSbomId)
      .map((sbom) => ({ id: sbom.id, label: sbom.label }));
  }
}
