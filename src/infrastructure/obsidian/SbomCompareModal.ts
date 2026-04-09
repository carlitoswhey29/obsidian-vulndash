import { Modal } from 'obsidian';
import type VulnDashPlugin from '../../plugin';

export class SbomCompareModal extends Modal {
  private leftSbomId = '';
  private rightSbomId = '';

  public constructor(
    private readonly plugin: VulnDashPlugin,
    initialSbomId?: string
  ) {
    super(plugin.app);
    const sboms = this.plugin.getSettings().sboms;
    this.leftSbomId = initialSbomId ?? sboms[0]?.id ?? '';
    this.rightSbomId = sboms.find((sbom) => sbom.id !== this.leftSbomId)?.id ?? sboms[1]?.id ?? '';
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-sbom-compare-modal');
    void this.renderAsync();
  }

  private async renderAsync(): Promise<void> {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h2', { text: 'Compare SBOMs' });

    const sboms = this.plugin.getSettings().sboms;
    if (sboms.length < 2) {
      contentEl.createEl('p', { text: 'Add at least two SBOMs to compare.' });
      return;
    }

    const picker = contentEl.createDiv({ cls: 'vulndash-sbom-compare-picker' });
    this.renderSelect(picker, 'SBOM A', sboms, this.leftSbomId, (value) => {
      this.leftSbomId = value;
      if (this.rightSbomId === value) {
        this.rightSbomId = sboms.find((sbom) => sbom.id !== value)?.id ?? this.rightSbomId;
      }
      void this.renderAsync();
    });
    this.renderSelect(picker, 'SBOM B', sboms, this.rightSbomId, (value) => {
      this.rightSbomId = value;
      if (this.leftSbomId === value) {
        this.leftSbomId = sboms.find((sbom) => sbom.id !== value)?.id ?? this.leftSbomId;
      }
      void this.renderAsync();
    });

    if (!this.leftSbomId || !this.rightSbomId || this.leftSbomId === this.rightSbomId) {
      contentEl.createEl('p', { text: 'Select two different SBOMs.' });
      return;
    }

    const comparison = await this.plugin.compareSboms(this.leftSbomId, this.rightSbomId);
    if (!comparison) {
      contentEl.createEl('p', { text: 'Unable to load both SBOMs for comparison.' });
      return;
    }

    const leftLabel = this.plugin.getSbomById(this.leftSbomId)?.label ?? 'SBOM A';
    const rightLabel = this.plugin.getSbomById(this.rightSbomId)?.label ?? 'SBOM B';
    contentEl.createEl('p', {
      text: `${leftLabel} vs ${rightLabel} | ${comparison.onlyInA.length} only in A | ${comparison.onlyInB.length} only in B | ${comparison.inBoth.length} in both`
    });

    this.renderListSection(contentEl, `Only in ${leftLabel}`, comparison.onlyInA);
    this.renderListSection(contentEl, `Only in ${rightLabel}`, comparison.onlyInB);
    this.renderListSection(contentEl, 'In Both', comparison.inBoth);
  }

  private renderSelect(
    container: HTMLElement,
    label: string,
    sboms: Array<{ id: string; label: string }>,
    selectedValue: string,
    onChange: (value: string) => void
  ): void {
    const field = container.createDiv({ cls: 'vulndash-sbom-compare-select' });
    field.createEl('label', { text: label });
    const select = field.createEl('select');
    for (const sbom of sboms) {
      const option = select.createEl('option', { text: sbom.label });
      option.value = sbom.id;
      option.selected = sbom.id === selectedValue;
    }
    select.addEventListener('change', () => onChange(select.value));
  }

  private renderListSection(container: HTMLElement, heading: string, values: string[]): void {
    container.createEl('h3', { text: heading });
    if (values.length === 0) {
      container.createEl('p', { text: 'None.' });
      return;
    }

    const list = container.createEl('ul');
    for (const value of values) {
      list.createEl('li', { text: value });
    }
  }
}
