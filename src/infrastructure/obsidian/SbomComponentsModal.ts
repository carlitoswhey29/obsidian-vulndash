import { Modal, Notice } from 'obsidian';
import type VulnDashPlugin from '../../plugin';
import type { ImportedSbomComponent } from '../../application/services/types';

export class SbomComponentsModal extends Modal {
  private searchQuery = '';

  public constructor(
    private readonly plugin: VulnDashPlugin,
    private readonly sbomId: string,
    private readonly onStateChanged?: () => void
  ) {
    super(plugin.app);
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-sbom-components-modal');
    this.render();
  }

  private render(): void {
    const { contentEl } = this;
    contentEl.empty();

    const sbom = this.plugin.getSbomById(this.sbomId);
    if (!sbom) {
      contentEl.createEl('p', { text: 'SBOM entry was not found.' });
      return;
    }

    contentEl.createEl('h2', { text: `${sbom.label}: Components` });
    contentEl.createEl('p', {
      text: `${sbom.components.length} stored component${sbom.components.length === 1 ? '' : 's'}.`
    });

    const searchInput = contentEl.createEl('input', {
      attr: {
        placeholder: 'Search components by name, version, namespace, purl, or cpe',
        type: 'search'
      }
    });
    searchInput.value = this.searchQuery;
    searchInput.addEventListener('input', (event) => {
      this.searchQuery = (event.target as HTMLInputElement).value.trim().toLowerCase();
      this.render();
    });

    const components = this.getFilteredComponents(sbom.components);
    if (components.length === 0) {
      contentEl.createEl('p', {
        text: sbom.components.length === 0
          ? 'This SBOM has no stored components.'
          : 'No components match the current search.'
      });
      return;
    }

    const list = contentEl.createDiv({ cls: 'vulndash-sbom-component-list' });
    for (const component of components) {
      this.renderComponentEditor(list, component);
    }
  }

  private getFilteredComponents(components: ImportedSbomComponent[]): ImportedSbomComponent[] {
    if (!this.searchQuery) {
      return components;
    }

    return components.filter((component) => {
      const haystack = [
        component.name,
        component.normalizedName,
        component.version,
        component.namespace,
        component.purl,
        component.cpe,
        component.bomRef
      ].join(' ').toLowerCase();

      return haystack.includes(this.searchQuery);
    });
  }

  private renderComponentEditor(container: HTMLElement, component: ImportedSbomComponent): void {
    const details = container.createEl('details', { cls: 'vulndash-sbom-component' });
    const summary = details.createEl('summary');
    const label = component.normalizedName || component.name || component.id;
    summary.createSpan({ text: label });
    if (component.version) {
      summary.createSpan({ text: ` (${component.version})` });
    }
    if (component.excluded) {
      summary.createSpan({ text: ' [excluded]' });
    }
    if (!component.enabled) {
      summary.createSpan({ text: ' [disabled]' });
    }

    const form = details.createDiv({ cls: 'vulndash-sbom-component-form' });
    this.createTextField(form, 'Name', component.name, async (value) => {
      await this.persistComponentChange(component.id, { name: value || component.name });
    });
    this.createTextField(form, 'Normalized Filter Name', component.normalizedName, async (value) => {
      await this.persistComponentChange(component.id, { normalizedName: value || component.normalizedName });
    });
    this.createTextField(form, 'Version', component.version, async (value) => {
      await this.persistComponentChange(component.id, { version: value });
    });
    this.createTextField(form, 'Namespace', component.namespace, async (value) => {
      await this.persistComponentChange(component.id, { namespace: value });
    });
    this.createTextField(form, 'PURL', component.purl, async (value) => {
      await this.persistComponentChange(component.id, { purl: value });
    });
    this.createTextField(form, 'CPE', component.cpe, async (value) => {
      await this.persistComponentChange(component.id, { cpe: value });
    });
    this.createTextField(form, 'BOM Ref', component.bomRef, async (value) => {
      await this.persistComponentChange(component.id, { bomRef: value });
    });

    this.createCheckboxField(form, 'Enabled', component.enabled, async (checked) => {
      await this.persistComponentChange(component.id, { enabled: checked });
    });
    this.createCheckboxField(form, 'Excluded from computed filters', component.excluded, async (checked) => {
      await this.persistComponentChange(component.id, { excluded: checked });
    });

    const actions = form.createDiv({ cls: 'vulndash-sbom-component-actions' });
    const removeButton = actions.createEl('button', { text: 'Remove Component' });
    removeButton.addEventListener('click', () => {
      void this.removeComponent(component.id);
    });
  }

  private createTextField(
    container: HTMLElement,
    label: string,
    value: string,
    onPersist: (value: string) => Promise<void>
  ): void {
    const wrapper = container.createDiv({ cls: 'vulndash-sbom-component-field' });
    wrapper.createEl('label', { text: label });
    const input = wrapper.createEl('input', { attr: { type: 'text' } });
    input.value = value;
    input.addEventListener('change', () => {
      void onPersist(input.value.trim());
    });
  }

  private createCheckboxField(
    container: HTMLElement,
    label: string,
    checked: boolean,
    onPersist: (checked: boolean) => Promise<void>
  ): void {
    const wrapper = container.createDiv({ cls: 'vulndash-sbom-component-field' });
    const checkboxLabel = wrapper.createEl('label');
    const input = checkboxLabel.createEl('input', { attr: { type: 'checkbox' } });
    input.checked = checked;
    checkboxLabel.appendText(` ${label}`);
    input.addEventListener('change', () => {
      void onPersist(input.checked);
    });
  }

  private async persistComponentChange(componentId: string, updates: Partial<ImportedSbomComponent>): Promise<void> {
    await this.plugin.updateSbomComponent(this.sbomId, componentId, updates);
    this.onStateChanged?.();
    this.render();
  }

  private async removeComponent(componentId: string): Promise<void> {
    await this.plugin.removeSbomComponent(this.sbomId, componentId);
    new Notice('SBOM component removed.');
    this.onStateChanged?.();
    this.render();
  }
}
