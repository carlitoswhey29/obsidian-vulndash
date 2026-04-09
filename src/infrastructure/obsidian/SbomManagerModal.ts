import { Modal, Notice } from 'obsidian';
import type { SbomFileChangeStatus } from '../../application/services/SbomImportService';
import type VulnDashPlugin from '../../plugin';
import { SbomCompareModal } from './SbomCompareModal';
import { SbomComponentsModal } from './SbomComponentsModal';

export class SbomManagerModal extends Modal {
  private renderId = 0;

  public constructor(
    private readonly plugin: VulnDashPlugin,
    private readonly onStateChanged?: () => void
  ) {
    super(plugin.app);
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-sbom-manager-modal');
    void this.renderAsync();
  }

  private async renderAsync(): Promise<void> {
    const activeRenderId = ++this.renderId;
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl('h2', { text: 'SBOM Management' });

    const settings = this.plugin.getSettings();
    const statuses = new Map(await Promise.all(settings.sboms.map(async (sbom) => (
      [sbom.id, await this.plugin.getSbomFileChangeStatus(sbom.id)] as const
    ))));

    if (activeRenderId !== this.renderId) {
      return;
    }

    const actionRow = contentEl.createDiv({ cls: 'vulndash-sbom-toolbar' });
    this.createButton(actionRow, 'Add SBOM', async () => {
      await this.plugin.addSbom();
      this.onStateChanged?.();
      await this.renderAsync();
    });
    this.createButton(actionRow, 'Sync All', async () => {
      const result = await this.plugin.syncAllSboms();
      new Notice(`SBOM sync complete. ${result.succeeded}/${result.total} succeeded, ${result.failed} failed.`);
      this.onStateChanged?.();
      await this.renderAsync();
    });
    this.createButton(actionRow, 'Compare SBOMs', async () => {
      new SbomCompareModal(this.plugin).open();
    }, settings.sboms.length < 2);

    if (settings.sboms.length === 0) {
      contentEl.createEl('p', { text: 'No SBOM entries configured yet.' });
      return;
    }

    for (const sbom of settings.sboms) {
      this.renderSbomCard(contentEl, sbom.id, statuses.get(sbom.id));
    }
  }

  private renderSbomCard(container: HTMLElement, sbomId: string, status: SbomFileChangeStatus | undefined): void {
    const sbom = this.plugin.getSbomById(sbomId);
    if (!sbom) {
      return;
    }

    const card = container.createDiv({ cls: 'vulndash-sbom-card' });
    const header = card.createDiv({ cls: 'vulndash-sbom-card-header' });
    header.createEl('h3', { text: sbom.label || 'Unnamed SBOM' });
    const toggleLabel = header.createEl('label', { cls: 'vulndash-sbom-toggle' });
    const toggle = toggleLabel.createEl('input', { attr: { type: 'checkbox' } });
    toggle.checked = sbom.enabled;
    toggleLabel.appendText(' Enabled');
    toggle.addEventListener('change', () => {
      void (async () => {
        await this.plugin.updateSbomConfig(sbom.id, { enabled: toggle.checked });
        this.onStateChanged?.();
        await this.renderAsync();
      })();
    });

    card.createEl('p', {
      cls: 'vulndash-sbom-meta',
      text: [
        `Path: ${sbom.path || 'not set'}`,
        `Namespace: ${sbom.namespace || 'none'}`,
        `Components: ${sbom.componentCount ?? 0}`,
        `Last sync: ${sbom.lastImportedAt ? new Date(sbom.lastImportedAt).toLocaleString() : 'never'}`,
        `File: ${this.describeFileStatus(status)}`,
        `Hash: ${sbom.contentHash ? sbom.contentHash.slice(0, 12) : 'none'}`
      ].join(' | ')
    });

    const form = card.createDiv({ cls: 'vulndash-sbom-form' });
    this.createTextField(form, 'Label', sbom.label, async (value) => {
      await this.plugin.updateSbomConfig(sbom.id, { label: value || sbom.label });
      this.onStateChanged?.();
    });
    this.createTextField(form, 'Path', sbom.path, async (value) => {
      await this.plugin.updateSbomConfig(sbom.id, { path: value });
      this.onStateChanged?.();
      await this.renderAsync();
    });
    this.createTextField(form, 'Namespace', sbom.namespace ?? '', async (value) => {
      await this.plugin.updateSbomConfig(sbom.id, { namespace: value });
      this.onStateChanged?.();
      await this.renderAsync();
    });

    const actions = card.createDiv({ cls: 'vulndash-sbom-toolbar' });
    this.createButton(actions, 'Sync', async () => {
      const result = await this.plugin.syncSbom(sbom.id);
      new Notice(result.message);
      this.onStateChanged?.();
      await this.renderAsync();
    });
    this.createButton(actions, 'Components', async () => {
      new SbomComponentsModal(this.plugin, sbom.id, () => {
        this.onStateChanged?.();
        void this.renderAsync();
      }).open();
    });
    this.createButton(actions, 'Compare', async () => {
      new SbomCompareModal(this.plugin, sbom.id).open();
    }, this.plugin.getSettings().sboms.length < 2);
    this.createButton(actions, 'Delete', async () => {
      if (!confirm(`Remove ${sbom.label}?`)) {
        return;
      }
      await this.plugin.removeSbom(sbom.id);
      new Notice(`Removed ${sbom.label}.`);
      this.onStateChanged?.();
      await this.renderAsync();
    }, false, true);

    if (sbom.lastError) {
      card.createEl('p', {
        cls: 'vulndash-sbom-error',
        text: `Last error: ${sbom.lastError}`
      });
    }
  }

  private createTextField(
    container: HTMLElement,
    label: string,
    value: string,
    onPersist: (value: string) => Promise<void>
  ): void {
    const wrapper = container.createDiv({ cls: 'vulndash-sbom-field' });
    wrapper.createEl('label', { text: label });
    const input = wrapper.createEl('input', { attr: { type: 'text' } });
    input.value = value;
    input.addEventListener('change', () => {
      void onPersist(input.value.trim());
    });
  }

  private createButton(
    container: HTMLElement,
    label: string,
    onClick: () => Promise<void>,
    disabled = false,
    warning = false
  ): void {
    const button = container.createEl('button', { text: label });
    button.disabled = disabled;
    if (warning) {
      button.addClass('mod-warning');
    }
    button.addEventListener('click', () => {
      void onClick();
    });
  }

  private describeFileStatus(status: SbomFileChangeStatus | undefined): string {
    if (!status) {
      return 'checking';
    }

    switch (status.status) {
      case 'changed':
        return 'changed';
      case 'missing':
        return 'missing';
      case 'not-imported':
        return 'not imported';
      case 'unchanged':
        return 'unchanged';
      case 'error':
      default:
        return status.error ?? 'error';
    }
  }
}
