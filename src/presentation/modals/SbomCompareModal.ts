import { Modal } from 'obsidian';
import type { SbomComparisonResult } from '../../application/use-cases/SbomComparisonService';
import { filterSbomComparisonResult } from '../../application/use-cases/SbomWorkspaceService';
import type VulnDashPlugin from '../plugin/VulnDashPlugin';
import { ImportedSbomConfig } from '../../application/use-cases/types';

export class SbomCompareModal extends Modal {
  private leftSbomId = '';
  private rightSbomId = '';
  private searchQuery = '';
  private comparison: SbomComparisonResult | null = null;
  private resultsEl: HTMLDivElement | null = null;

  public constructor(
    private readonly plugin: VulnDashPlugin,
    initialSbomId?: string
  ) {
    super(plugin.app);
    const sboms = this.plugin.getSettings().sboms;
    this.leftSbomId = initialSbomId ?? sboms[0]?.id ?? '';
    this.rightSbomId = sboms.find((sbom: ImportedSbomConfig) => sbom.id !== this.leftSbomId)?.id ?? sboms[1]?.id ?? '';
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-sbom-compare-modal');
    void this.renderAsync();
  }

  private async renderAsync(): Promise<void> {
    const { contentEl } = this;
    contentEl.empty();
    this.resultsEl = null;

    const header = contentEl.createDiv({ cls: 'vulndash-modal-header' });
    header.createEl('h2', { text: 'Compare SBOMs' });
    header.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Review which components are unique to each SBOM and which overlap across both selections.'
    });

    const sboms = this.plugin.getSettings().sboms;
    if (sboms.length < 2) {
      this.renderEmptyState(contentEl, 'Not enough SBOMs to compare', 'Add and configure at least two SBOMs before opening comparison.');
      return;
    }

    const picker = contentEl.createDiv({ cls: 'vulndash-sbom-compare-toolbar' });
    this.renderSelect(picker, 'SBOM A', sboms, this.leftSbomId, async (value) => {
      this.leftSbomId = value;
      if (this.rightSbomId === value) {
        this.rightSbomId = sboms.find((sbom: ImportedSbomConfig) => sbom.id !== value)?.id ?? this.rightSbomId;
      }
      await this.renderAsync();
    });
    this.renderSelect(picker, 'SBOM B', sboms, this.rightSbomId, async (value) => {
      this.rightSbomId = value;
      if (this.leftSbomId === value) {
        this.leftSbomId = sboms.find((sbom: ImportedSbomConfig) => sbom.id !== value)?.id ?? this.leftSbomId;
      }
      await this.renderAsync();
    });

    const swapButton = picker.createEl('button', { text: 'Swap' });
    swapButton.addEventListener('click', () => {
      const nextLeft = this.rightSbomId;
      this.rightSbomId = this.leftSbomId;
      this.leftSbomId = nextLeft;
      void this.renderAsync();
    });

    const searchInput = contentEl.createEl('input', {
      attr: {
        placeholder: 'Filter compared component names',
        type: 'search'
      }
    });
    searchInput.value = this.searchQuery;
    searchInput.addEventListener('input', () => {
      this.searchQuery = searchInput.value;
      this.renderResults();
    });

    this.resultsEl = contentEl.createDiv({ cls: 'vulndash-sbom-compare-results' });
    await this.loadComparison();
    this.renderResults();
  }

  private async loadComparison(): Promise<void> {
    if (!this.leftSbomId || !this.rightSbomId || this.leftSbomId === this.rightSbomId) {
      this.comparison = null;
      return;
    }

    this.comparison = await this.plugin.compareSboms(this.leftSbomId, this.rightSbomId);
  }

  private renderResults(): void {
    if (!this.resultsEl) {
      return;
    }

    this.resultsEl.empty();
    if (!this.leftSbomId || !this.rightSbomId || this.leftSbomId === this.rightSbomId) {
      this.renderEmptyState(this.resultsEl, 'Choose two different SBOMs', 'Select two distinct SBOM entries to load a comparison.');
      return;
    }

    if (!this.comparison) {
      this.renderEmptyState(this.resultsEl, 'Comparison unavailable', 'One or both SBOMs could not be loaded. Check their file selections and sync state.');
      return;
    }

    const leftLabel = this.plugin.getSbomById(this.leftSbomId)?.label ?? 'SBOM A';
    const rightLabel = this.plugin.getSbomById(this.rightSbomId)?.label ?? 'SBOM B';
    const filteredComparison = filterSbomComparisonResult(this.comparison, this.searchQuery);

    const summary = this.resultsEl.createDiv({ cls: 'vulndash-sbom-summary-grid' });
    this.createSummaryStat(summary, `Only in ${leftLabel}`, String(filteredComparison.onlyInA.length));
    this.createSummaryStat(summary, `Only in ${rightLabel}`, String(filteredComparison.onlyInB.length));
    this.createSummaryStat(summary, 'In both', String(filteredComparison.inBoth.length));

    const sections = this.resultsEl.createDiv({ cls: 'vulndash-sbom-compare-section-grid' });
    this.renderListSection(sections, `Only in ${leftLabel}`, filteredComparison.onlyInA, 'Components that appear only in the left-hand SBOM.');
    this.renderListSection(sections, `Only in ${rightLabel}`, filteredComparison.onlyInB, 'Components that appear only in the right-hand SBOM.');
    this.renderListSection(sections, 'In both', filteredComparison.inBoth, 'Components shared by both selected SBOMs.');
  }

  private renderSelect(
    container: HTMLElement,
    label: string,
    sboms: Array<{ id: string; label: string }>,
    selectedValue: string,
    onChange: (value: string) => Promise<void>
  ): void {
    const field = container.createDiv({ cls: 'vulndash-sbom-compare-select' });
    field.createEl('label', { text: label });
    const select = field.createEl('select');
    for (const sbom of sboms) {
      const option = select.createEl('option', { text: sbom.label });
      option.value = sbom.id;
      option.selected = sbom.id === selectedValue;
    }

    select.addEventListener('change', () => {
      void onChange(select.value);
    });
  }

  private renderListSection(container: HTMLElement, heading: string, values: string[], helperText: string): void {
    const section = container.createDiv({ cls: 'vulndash-sbom-compare-section' });
    section.createEl('h3', { text: `${heading} (${values.length})` });
    section.createEl('p', { cls: 'vulndash-muted-copy', text: helperText });
    if (values.length === 0) {
      section.createEl('p', { text: 'No components in this group.' });
      return;
    }

    const list = section.createEl('ul', { cls: 'vulndash-sbom-compare-list' });
    for (const value of values) {
      list.createEl('li', { text: value });
    }
  }

  private createSummaryStat(container: HTMLElement, label: string, value: string): void {
    const stat = container.createDiv({ cls: 'vulndash-sbom-summary-stat' });
    stat.createDiv({ cls: 'vulndash-sbom-summary-value', text: value });
    stat.createDiv({ cls: 'vulndash-sbom-summary-label', text: label });
  }

  private renderEmptyState(container: HTMLElement, title: string, body: string): void {
    const state = container.createDiv({ cls: 'vulndash-empty-state is-compact' });
    state.createEl('h3', { text: title });
    state.createEl('p', { text: body });
  }
}
