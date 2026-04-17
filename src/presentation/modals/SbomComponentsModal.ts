import { Modal, Notice } from 'obsidian';
import type { ResolvedSbomComponent } from '../../application/use-cases/types';
import type VulnDashPlugin from '../plugin/VulnDashPlugin';

interface EditableSbomComponent extends ResolvedSbomComponent {
  draftEditedName: string;
}

const toEditableComponent = (component: ResolvedSbomComponent): EditableSbomComponent => ({
  ...component,
  draftEditedName: component.editedName ?? ''
});

const getComponentDisplayName = (component: EditableSbomComponent): string =>
  component.editedName?.trim() || component.normalizedName;

export class SbomComponentsModal extends Modal {
  private searchQuery = '';
  private renderId = 0;
  private components: EditableSbomComponent[] = [];
  private listEl: HTMLDivElement | null = null;
  private emptyStateEl: HTMLDivElement | null = null;
  private resultCountEl: HTMLParagraphElement | null = null;

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
    this.resultCountEl = null;

    const sbom = this.plugin.getSbomById(this.sbomId);
    if (!sbom) {
      this.renderMessageState(contentEl, 'SBOM not found', 'This SBOM entry is no longer available.');
      return;
    }

    const components = await this.plugin.getSbomComponents(this.sbomId);
    if (activeRenderId !== this.renderId) {
      return;
    }

    const header = contentEl.createDiv({ cls: 'vulndash-modal-header' });
    header.createEl('h2', { text: `${sbom.label}: Components` });
    header.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Review runtime components, adjust the display name used for filtering, and control whether each component participates in computed filters.'
    });

    if (!components) {
      this.renderMessageState(contentEl, 'Unable to load components', sbom.lastError || 'The SBOM file could not be parsed into components.');
      return;
    }

    this.components = components.map(toEditableComponent);

    const toolbar = contentEl.createDiv({ cls: 'vulndash-sbom-component-toolbar' });
    const searchInput = toolbar.createEl('input', {
      attr: {
        placeholder: 'Search by original, normalized, or display name',
        type: 'search'
      }
    });
    searchInput.value = this.searchQuery;
    searchInput.addEventListener('input', () => {
      this.searchQuery = searchInput.value;
      this.renderComponentList();
    });

    this.resultCountEl = contentEl.createEl('p', { cls: 'vulndash-muted-copy' });
    this.emptyStateEl = contentEl.createDiv({ cls: 'vulndash-empty-state is-compact' });
    this.listEl = contentEl.createDiv({ cls: 'vulndash-sbom-component-list' });
    this.renderComponentList();
  }

  private renderComponentList(): void {
    if (!this.listEl || !this.emptyStateEl || !this.resultCountEl) {
      return;
    }

    this.listEl.empty();
    const filteredComponents = this.getFilteredComponents(this.components);
    this.resultCountEl.setText(`${filteredComponents.length} of ${this.components.length} component${this.components.length === 1 ? '' : 's'} shown.`);

    if (filteredComponents.length === 0) {
      this.emptyStateEl.empty();
      this.emptyStateEl.createEl('h3', { text: this.components.length === 0 ? 'No components found' : 'No matching components' });
      this.emptyStateEl.createEl('p', {
        text: this.components.length === 0
          ? 'This SBOM file was readable, but it did not contain any components to inspect.'
          : 'Try a broader search or clear the current filter.'
      });
      this.emptyStateEl.style.display = '';
      this.listEl.style.display = 'none';
      return;
    }

    this.emptyStateEl.empty();
    this.emptyStateEl.style.display = 'none';
    this.listEl.style.display = '';

    for (const component of filteredComponents) {
      this.renderComponentRow(this.listEl, component);
    }
  }

  private getFilteredComponents(components: EditableSbomComponent[]): EditableSbomComponent[] {
    const normalizedQuery = this.searchQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return components;
    }

    return components.filter((component) => [
      component.originalName,
      component.normalizedName,
      getComponentDisplayName(component),
      component.draftEditedName
    ].join(' ').toLowerCase().includes(normalizedQuery));
  }

  private renderComponentRow(container: HTMLElement, component: EditableSbomComponent): void {
    const row = container.createDiv({ cls: 'vulndash-sbom-component-row' });
    const top = row.createDiv({ cls: 'vulndash-sbom-component-row-top' });
    const names = top.createDiv({ cls: 'vulndash-sbom-component-names' });
    const currentNameEl = names.createEl('h3', { text: getComponentDisplayName(component) });
    names.createEl('p', {
      cls: 'vulndash-sbom-component-meta',
      text: `Original: ${component.originalName} • Normalized import: ${component.normalizedName}`
    });

    const badges = top.createDiv({ cls: 'vulndash-sbom-badges' });
    badges.createSpan({
      cls: `vulndash-badge ${component.excluded ? 'vulndash-badge-warning' : 'vulndash-badge-success'}`,
      text: component.excluded ? 'Excluded' : 'Included'
    });
    if (component.editedName) {
      badges.createSpan({ cls: 'vulndash-badge vulndash-badge-neutral', text: 'Override active' });
    }

    const grid = row.createDiv({ cls: 'vulndash-sbom-component-grid' });

    const nameField = grid.createDiv({ cls: 'vulndash-sbom-component-field' });
    nameField.createEl('label', { text: 'Display name override' });
    const nameInput = nameField.createEl('input', {
      attr: {
        placeholder: component.normalizedName,
        type: 'text'
      }
    });
    nameInput.value = component.draftEditedName || component.editedName || '';
    nameInput.addEventListener('input', () => {
      component.draftEditedName = nameInput.value;
      currentNameEl.setText(nameInput.value.trim() || component.editedName || component.normalizedName);
    });
    nameInput.addEventListener('blur', () => {
      const nextEditedName = nameInput.value.trim();
      if (nextEditedName === (component.editedName ?? '')) {
        return;
      }

      nameInput.classList.add('vulndash-input-saving');
      void (async () => {
        try {
          await this.persistComponentChange(component, {
            editedName: nextEditedName
          });
          if (nextEditedName) {
            component.editedName = nextEditedName;
          } else {
            delete component.editedName;
          }
          component.draftEditedName = nextEditedName;
          currentNameEl.setText(getComponentDisplayName(component));
          nameInput.classList.add('vulndash-input-saved');
          window.setTimeout(() => nameInput.classList.remove('vulndash-input-saved'), 600);
          this.renderComponentList();
        } catch {
          component.draftEditedName = component.editedName ?? '';
          nameInput.value = component.draftEditedName;
          currentNameEl.setText(getComponentDisplayName(component));
        } finally {
          nameInput.classList.remove('vulndash-input-saving');
        }
      })();
    });

    const excludeField = grid.createDiv({ cls: 'vulndash-sbom-component-field' });
    excludeField.createEl('label', { text: 'Filter participation' });
    const excludeLabel = excludeField.createEl('label', { cls: 'vulndash-sbom-checkbox' });
    const excludeInput = excludeLabel.createEl('input', { attr: { type: 'checkbox' } });
    excludeInput.checked = component.excluded;
    excludeLabel.appendText(' Exclude this component from computed filters');
    excludeInput.addEventListener('change', () => {
      const nextExcluded = excludeInput.checked;
      void (async () => {
        try {
          await this.persistComponentChange(component, { excluded: nextExcluded });
          component.excluded = nextExcluded;
          this.renderComponentList();
        } catch {
          excludeInput.checked = component.excluded;
        }
      })();
    });

    const actions = row.createDiv({ cls: 'vulndash-sbom-component-actions' });
    const resetButton = actions.createEl('button', { text: 'Reset Override' });
    resetButton.addEventListener('click', () => {
      void (async () => {
        await this.persistComponentChange(component, {
          editedName: '',
          excluded: false
        });
        delete component.editedName;
        component.draftEditedName = '';
        component.excluded = false;
        this.renderComponentList();
      })();
    });

    const removeButton = actions.createEl('button', { text: 'Remove From Filters' });
    removeButton.addClass('mod-warning');
    removeButton.addEventListener('click', () => {
      void this.removeComponent(component);
    });
  }

  private async persistComponentChange(
    component: EditableSbomComponent,
    updates: { editedName?: string; excluded?: boolean }
  ): Promise<void> {
    const editedName = updates.editedName?.trim() ?? component.editedName ?? '';
    await this.plugin.updateSbomComponentOverride(this.sbomId, component.originalName, {
      editedName: editedName && editedName !== component.normalizedName ? editedName : '',
      excluded: updates.excluded ?? component.excluded
    });
    this.onStateChanged?.();
  }

  private async removeComponent(component: EditableSbomComponent): Promise<void> {
    await this.plugin.removeSbomComponent(this.sbomId, component.originalName);
    component.excluded = true;
    new Notice('Component removed from computed filters. Use Reset Override to include it again.');
    this.onStateChanged?.();
    this.renderComponentList();
  }

  private renderMessageState(container: HTMLElement, title: string, body: string): void {
    const state = container.createDiv({ cls: 'vulndash-empty-state' });
    state.createEl('h3', { text: title });
    state.createEl('p', { text: body });
  }
}
