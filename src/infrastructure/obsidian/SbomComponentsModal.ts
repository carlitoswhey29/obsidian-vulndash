import { Modal, Notice } from 'obsidian';
import type { ResolvedSbomComponent } from '../../application/services/types';
import type VulnDashPlugin from '../../plugin';

export class SbomComponentsModal extends Modal {
  private searchQuery = '';
  private renderId = 0;
  private components: ResolvedSbomComponent[] = [];
  private listEl: HTMLDivElement | null = null;
  private emptyStateEl: HTMLParagraphElement | null = null;

  public constructor(
    private readonly plugin: VulnDashPlugin,
    private readonly sbomId: string,
    private readonly onStateChanged?: () => void
  ) {
    super(plugin.app);
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-sbom-components-modal');
    void this.renderAsync();
  }

  private async renderAsync(): Promise<void> {
    const activeRenderId = ++this.renderId;
    const { contentEl } = this;
    contentEl.empty();
    this.listEl = null;
    this.emptyStateEl = null;

    const sbom = this.plugin.getSbomById(this.sbomId);
    if (!sbom) {
      contentEl.createEl('p', { text: 'SBOM entry was not found.' });
      return;
    }

    const components = await this.plugin.getSbomComponents(this.sbomId);
    if (activeRenderId !== this.renderId) {
      return;
    }

    contentEl.createEl('h2', { text: `${sbom.label}: Components` });
    if (!components) {
      contentEl.createEl('p', { text: sbom.lastError || 'Unable to load components for this SBOM.' });
      return;
    }

    this.components = components;
    contentEl.createEl('p', {
      text: `${components.length} runtime component${components.length === 1 ? '' : 's'}. Changes here persist as overrides only.`
    });

    const searchInput = contentEl.createEl('input', {
      attr: {
        placeholder: 'Search by original or effective name',
        type: 'search'
      }
    });
    searchInput.value = this.searchQuery;
    searchInput.addEventListener('input', (event) => {
      this.searchQuery = (event.target as HTMLInputElement).value.trim().toLowerCase();
      this.renderComponentList();
    });

    this.emptyStateEl = contentEl.createEl('p');
    this.listEl = contentEl.createDiv({ cls: 'vulndash-sbom-component-list' });
    this.renderComponentList();
  }

  private renderComponentList(): void {
    if (!this.listEl || !this.emptyStateEl) {
      return;
    }

    this.listEl.empty();
    const filteredComponents = this.getFilteredComponents(this.components);
    if (filteredComponents.length === 0) {
      this.emptyStateEl.setText(this.components.length === 0
        ? 'This SBOM has no components.'
        : 'No components match the current search.');
      this.listEl.style.display = 'none';
      return;
    }

    this.emptyStateEl.empty();
    this.listEl.style.display = '';
    for (const component of filteredComponents) {
      this.renderComponentEditor(this.listEl, component);
    }
  }

  private getFilteredComponents(components: ResolvedSbomComponent[]): ResolvedSbomComponent[] {
    if (!this.searchQuery) {
      return components;
    }

    return components.filter((component) => [
      component.originalName,
      component.normalizedName,
      component.displayName
    ].join(' ').toLowerCase().includes(this.searchQuery));
  }

  private renderComponentEditor(container: HTMLElement, component: ResolvedSbomComponent): void {
    const details = container.createEl('details', { cls: 'vulndash-sbom-component' });
    const summary = details.createEl('summary');
    summary.createSpan({ text: component.displayName });
    if (component.displayName !== component.originalName) {
      summary.createSpan({ text: ` (${component.originalName})` });
    }
    if (component.excluded) {
      summary.createSpan({ text: ' [excluded]' });
    }

    const form = details.createDiv({ cls: 'vulndash-sbom-component-form' });
    form.createEl('p', {
      cls: 'vulndash-sbom-component-meta',
      text: `Original name: ${component.originalName} | Normalized import: ${component.normalizedName}`
    });

    const nameField = form.createDiv({ cls: 'vulndash-sbom-component-field' });
    nameField.createEl('label', { text: 'Effective filter name' });
    const nameInput = nameField.createEl('input', { attr: { type: 'text' } });
    let draftName = component.editedName ?? component.normalizedName;
    let committedName = draftName;
    nameInput.value = committedName;
    nameInput.addEventListener('input', () => {
      draftName = nameInput.value;
    });
    nameInput.addEventListener('blur', () => {
      const nextName = draftName.trim() || component.normalizedName;
      if (nextName === committedName) {
        return;
      }

      nameInput.classList.add('vulndash-input-saving');
      void (async () => {
        try {
          await this.persistComponentChange(component, {
            editedName: nextName
          });
          committedName = nextName;
          nameInput.value = nextName;
          nameInput.classList.add('vulndash-input-saved');
          window.setTimeout(() => {
            nameInput.classList.remove('vulndash-input-saved');
          }, 600);
        } catch {
          draftName = committedName;
          nameInput.value = committedName;
        } finally {
          nameInput.classList.remove('vulndash-input-saving');
        }
      })();
    });

    const excludeField = form.createDiv({ cls: 'vulndash-sbom-component-field' });
    const excludeLabel = excludeField.createEl('label');
    const excludeInput = excludeLabel.createEl('input', { attr: { type: 'checkbox' } });
    excludeInput.checked = component.excluded;
    excludeLabel.appendText(' Exclude from computed filters');
    excludeInput.addEventListener('change', () => {
      void this.persistComponentChange(component, { excluded: excludeInput.checked });
    });

    const actions = form.createDiv({ cls: 'vulndash-sbom-component-actions' });
    const resetButton = actions.createEl('button', { text: 'Reset override' });
    resetButton.addEventListener('click', () => {
      void this.persistComponentChange(component, {
        editedName: '',
        excluded: false
      });
    });

    const removeButton = actions.createEl('button', { text: 'Remove component' });
    removeButton.addClass('mod-warning');
    removeButton.addEventListener('click', () => {
      void this.removeComponent(component);
    });
  }

  private async persistComponentChange(
    component: ResolvedSbomComponent,
    updates: { editedName?: string; excluded?: boolean }
  ): Promise<void> {
    const editedName = updates.editedName?.trim() ?? component.editedName ?? '';
    await this.plugin.updateSbomComponentOverride(this.sbomId, component.originalName, {
      editedName: editedName && editedName !== component.normalizedName ? editedName : '',
      excluded: updates.excluded ?? component.excluded
    });
    this.onStateChanged?.();
    await this.renderAsync();
  }

  private async removeComponent(component: ResolvedSbomComponent): Promise<void> {
    await this.plugin.removeSbomComponent(this.sbomId, component.originalName);
    new Notice('SBOM component removed from computed filters.');
    this.onStateChanged?.();
    await this.renderAsync();
  }
}
