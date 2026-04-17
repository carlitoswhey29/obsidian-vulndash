import { Modal, Notice, setIcon } from 'obsidian';
import type { ProjectNoteLookupResult } from '../../application/correlation/ResolveAffectedProjects';
import type { SbomFileChangeStatus } from '../../application/use-cases/SbomImportService';
import type { ImportedSbomConfig } from '../../application/use-cases/types';
import {
  describeSbomFileStatus,
  filterSbomsForWorkspace,
  summarizeSbomWorkspace
} from '../../application/use-cases/SbomWorkspaceService';
import type VulnDashPlugin from '../plugin/VulnDashPlugin';
import { ProjectNoteSuggestModal } from './ProjectNoteSuggestModal';
import { SbomCompareModal } from './SbomCompareModal';
import { SbomComponentsModal } from './SbomComponentsModal';
import { SbomFileSuggestModal } from './SbomFileSuggestModal';

export const saveSbomProjectNoteMapping = async (
  plugin: Pick<VulnDashPlugin, 'linkSbomToProjectNote'>,
  sbomId: string,
  notePath: string
): Promise<void> => {
  await plugin.linkSbomToProjectNote(sbomId, notePath);
};

export const clearSbomProjectNoteMapping = async (
  plugin: Pick<VulnDashPlugin, 'clearSbomProjectNote'>,
  sbomId: string
): Promise<void> => {
  await plugin.clearSbomProjectNote(sbomId);
};

export class SbomManagerModal extends Modal {
  private renderId = 0;
  private searchQuery = '';
  private statusMap = new Map<string, SbomFileChangeStatus>();
  private projectNoteStatusMap = new Map<string, ProjectNoteLookupResult | null>();
  private listHostEl: HTMLDivElement | null = null;

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
    const settings = this.plugin.getSettings();
    const [statuses, projectNoteStatuses] = await Promise.all([
      this.plugin.getSbomFileStatuses(),
      this.plugin.getSbomProjectNoteStatuses()
    ]);
    if (activeRenderId !== this.renderId) {
      return;
    }

    this.statusMap = statuses;
    this.projectNoteStatusMap = projectNoteStatuses;
    const { contentEl } = this;
    contentEl.empty();
    this.listHostEl = null;

    const header = contentEl.createDiv({ cls: 'vulndash-modal-header' });
    header.createEl('h2', { text: 'SBOM Manager' });
    header.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Browse vault files, inspect components, sync changes, compare SBOMs, and map each workspace to an explicit project note.'
    });

    this.renderWorkspaceSummary(contentEl, settings.sboms);
    this.renderActionBar(contentEl, settings.sboms.length);

    this.listHostEl = contentEl.createDiv();
    this.renderSbomList();
  }

  private renderWorkspaceSummary(container: HTMLElement, sboms: ImportedSbomConfig[]): void {
    const summary = summarizeSbomWorkspace(sboms, this.statusMap);
    const stats = container.createDiv({ cls: 'vulndash-sbom-summary-grid' });

    this.createSummaryStat(stats, 'Configured', String(summary.configured));
    this.createSummaryStat(stats, 'Enabled', String(summary.enabled));
    this.createSummaryStat(stats, 'Errors', String(summary.withErrors));
    this.createSummaryStat(stats, 'Changed', String(summary.changed));
  }

  private renderActionBar(container: HTMLElement, sbomCount: number): void {
    const actionBar = container.createDiv({ cls: 'vulndash-sbom-workspace-toolbar' });

    const searchField = actionBar.createDiv({ cls: 'vulndash-sbom-search' });
    const searchIcon = searchField.createSpan({ cls: 'vulndash-sbom-search-icon' });
    setIcon(searchIcon, 'search');
    const searchInput = searchField.createEl('input', {
      attr: {
        placeholder: 'Filter SBOMs by label, path, namespace, or error',
        type: 'search'
      }
    });
    searchInput.value = this.searchQuery;
    searchInput.addEventListener('input', () => {
      this.searchQuery = searchInput.value;
      this.renderSbomList();
    });

    const actions = actionBar.createDiv({ cls: 'vulndash-sbom-toolbar' });
    this.createButton(actions, 'Add SBOM', async () => {
      await this.addSbomAndBrowse();
    }, { cta: true });
    this.createButton(actions, 'Sync All', async () => {
      const result = await this.plugin.syncAllSboms();
      new Notice(`SBOM sync finished. ${result.succeeded}/${result.total} succeeded.`);
      this.onStateChanged?.();
      await this.renderAsync();
    }, { disabled: sbomCount === 0 });
    this.createButton(actions, 'Compare', async () => {
      new SbomCompareModal(this.plugin).open();
    }, { disabled: sbomCount < 2 });
    this.createButton(actions, 'Refresh', async () => {
      await this.renderAsync();
    }, { quiet: true });
  }

  private renderSbomCard(container: HTMLElement, sbom: ImportedSbomConfig): void {
    const fileStatus = describeSbomFileStatus(this.statusMap.get(sbom.id));
    const projectNoteStatus = this.projectNoteStatusMap.get(sbom.id) ?? null;
    const card = container.createDiv({ cls: 'vulndash-sbom-workspace-card' });

    const header = card.createDiv({ cls: 'vulndash-sbom-card-header' });
    const titleBlock = header.createDiv({ cls: 'vulndash-sbom-card-title' });
    const titleEl = titleBlock.createEl('h3', { text: sbom.label || 'Untitled SBOM' });
    titleBlock.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: sbom.path || 'No file selected yet. Use Browse to attach a vault JSON SBOM.'
    });

    const badges = header.createDiv({ cls: 'vulndash-sbom-badges' });
    this.createBadge(badges, sbom.enabled ? 'Enabled' : 'Disabled', sbom.enabled ? 'success' : 'neutral');
    this.createBadge(badges, fileStatus.label, fileStatus.tone);
    if (sbom.lastError) {
      this.createBadge(badges, 'Attention needed', 'danger');
    }
    if (projectNoteStatus?.status === 'broken') {
      this.createBadge(badges, 'Project note missing', 'warning');
    }
    if (!sbom.linkedProjectNotePath) {
      this.createBadge(badges, 'Unmapped findings', 'neutral');
    }

    const metrics = card.createDiv({ cls: 'vulndash-sbom-metrics' });
    this.createMetric(metrics, 'Components', String(sbom.componentCount ?? 0));
    this.createMetric(metrics, 'Last sync', sbom.lastImportedAt ? new Date(sbom.lastImportedAt).toLocaleString() : 'Never');
    this.createMetric(metrics, 'Namespace', sbom.namespace || 'None');

    const filePanel = card.createDiv({ cls: 'vulndash-sbom-file-panel' });
    filePanel.createDiv({ cls: 'vulndash-sbom-file-label', text: sbom.path ? 'Selected file' : 'File selection' });
    filePanel.createDiv({
      cls: sbom.path ? 'vulndash-sbom-file-path' : 'vulndash-sbom-file-path is-empty',
      text: sbom.path || 'Choose a vault JSON file to connect this SBOM entry.'
    });

    const projectPanel = card.createDiv({ cls: 'vulndash-sbom-file-panel' });
    projectPanel.createDiv({ cls: 'vulndash-sbom-file-label', text: 'Mapped project note' });
    projectPanel.createDiv({
      cls: sbom.linkedProjectNotePath ? 'vulndash-sbom-file-path' : 'vulndash-sbom-file-path is-empty',
      text: this.describeProjectNoteStatus(sbom, projectNoteStatus)
    });

    const projectActions = card.createDiv({ cls: 'vulndash-sbom-toolbar' });
    this.createButton(projectActions, this.getProjectNoteActionLabel(sbom, projectNoteStatus), async () => {
      this.openProjectNotePicker(sbom.id);
    }, { cta: !sbom.linkedProjectNotePath });
    this.createButton(projectActions, 'Open Project Note', async () => {
      if (projectNoteStatus) {
        await this.plugin.openNotePath(projectNoteStatus.notePath);
      }
    }, { disabled: projectNoteStatus?.status !== 'linked' });
    this.createButton(projectActions, 'Clear Project Link', async () => {
      await clearSbomProjectNoteMapping(this.plugin, sbom.id);
      new Notice(`Cleared the project note mapping for ${sbom.label}.`);
      this.onStateChanged?.();
      await this.renderAsync();
    }, { disabled: !sbom.linkedProjectNotePath, quiet: true });

    const primaryActions = card.createDiv({ cls: 'vulndash-sbom-toolbar' });
    this.createButton(primaryActions, sbom.path ? 'Change File' : 'Browse File', async () => {
      this.openSbomFilePicker(sbom.id);
    }, { cta: !sbom.path });
    this.createButton(primaryActions, 'Inspect Components', async () => {
      new SbomComponentsModal(this.plugin, sbom.id, () => {
        this.onStateChanged?.();
        void this.renderAsync();
      }).open();
    }, { disabled: !sbom.path });
    this.createButton(primaryActions, 'Sync', async () => {
      const result = await this.plugin.syncSbom(sbom.id);
      new Notice(result.message);
      this.onStateChanged?.();
      await this.renderAsync();
    }, { disabled: !sbom.path });
    this.createButton(primaryActions, 'Compare', async () => {
      new SbomCompareModal(this.plugin, sbom.id).open();
    }, { disabled: this.plugin.getSettings().sboms.length < 2 || !sbom.path });
    this.createButton(primaryActions, sbom.enabled ? 'Disable' : 'Enable', async () => {
      await this.plugin.updateSbomConfig(sbom.id, { enabled: !sbom.enabled });
      this.onStateChanged?.();
      await this.renderAsync();
    });
    this.createButton(primaryActions, 'Remove', async () => {
      if (!confirm(`Remove ${sbom.label}?`)) {
        return;
      }

      await this.plugin.removeSbom(sbom.id);
      new Notice(`Removed ${sbom.label}.`);
      this.onStateChanged?.();
      await this.renderAsync();
    }, { warning: true });

    const advanced = card.createEl('details', { cls: 'vulndash-sbom-advanced' });
    advanced.createEl('summary', { text: 'Details and fallback path entry' });
    const advancedGrid = advanced.createDiv({ cls: 'vulndash-sbom-advanced-grid' });

    this.createBlurPersistedField(advancedGrid, {
      initialValue: sbom.label,
      label: 'Project label',
      onPersist: async (value) => {
        const nextValue = value.trim() || sbom.label;
        await this.plugin.updateSbomConfig(sbom.id, { label: nextValue });
        this.onStateChanged?.();
        titleEl.setText(nextValue || 'Untitled SBOM');
        return nextValue;
      },
      placeholder: 'Production web platform'
    });

    this.createBlurPersistedField(advancedGrid, {
      initialValue: sbom.namespace ?? '',
      label: 'Namespace',
      onPersist: async (value) => {
        const nextValue = value.trim();
        await this.plugin.updateSbomConfig(sbom.id, { namespace: nextValue });
        this.onStateChanged?.();
        return nextValue;
      },
      placeholder: 'Optional namespace'
    });

    this.createManualPathField(advancedGrid, sbom);

    if (sbom.lastError) {
      card.createDiv({
        cls: 'vulndash-sbom-error',
        text: sbom.lastError
      });
    }
  }

  private createManualPathField(container: HTMLElement, sbom: ImportedSbomConfig): void {
    const wrapper = container.createDiv({ cls: 'vulndash-sbom-field' });
    wrapper.createEl('label', { text: 'Manual path fallback' });
    wrapper.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Browse is the recommended flow. Use this only when you need to paste a vault-relative path manually.'
    });

    const controls = wrapper.createDiv({ cls: 'vulndash-sbom-inline-controls' });
    const input = controls.createEl('input', {
      attr: {
        placeholder: 'reports/sbom.json',
        type: 'text'
      }
    });
    input.value = sbom.path;

    const button = controls.createEl('button', { text: 'Attach Path' });
    button.addEventListener('click', () => {
      void this.attachSbomFile(sbom.id, input.value.trim());
    });
  }

  private createBlurPersistedField(
    container: HTMLElement,
    options: {
      initialValue: string;
      label: string;
      onPersist: (value: string) => Promise<string>;
      placeholder?: string;
    }
  ): void {
    let draftValue = options.initialValue;
    let committedValue = options.initialValue;

    const wrapper = container.createDiv({ cls: 'vulndash-sbom-field' });
    wrapper.createEl('label', { text: options.label });
    const input = wrapper.createEl('input', { attr: { type: 'text' } });
    input.value = options.initialValue;
    if (options.placeholder) {
      input.placeholder = options.placeholder;
    }

    input.addEventListener('input', () => {
      draftValue = input.value;
    });

    input.addEventListener('blur', () => {
      const nextValue = draftValue.trim();
      if (nextValue === committedValue) {
        return;
      }

      input.classList.add('vulndash-input-saving');
      void (async () => {
        try {
          const persistedValue = await options.onPersist(nextValue);
          committedValue = persistedValue;
          draftValue = persistedValue;
          input.value = persistedValue;
          input.classList.add('vulndash-input-saved');
          window.setTimeout(() => input.classList.remove('vulndash-input-saved'), 600);
        } catch {
          draftValue = committedValue;
          input.value = committedValue;
        } finally {
          input.classList.remove('vulndash-input-saving');
        }
      })();
    });
  }

  private createButton(
    container: HTMLElement,
    label: string,
    onClick: () => Promise<void>,
    options: {
      cta?: boolean;
      disabled?: boolean;
      quiet?: boolean;
      warning?: boolean;
    } = {}
  ): void {
    const button = container.createEl('button', { text: label });
    button.disabled = options.disabled ?? false;
    if (options.cta) {
      button.addClass('mod-cta');
    }
    if (options.quiet) {
      button.addClass('mod-muted');
    }
    if (options.warning) {
      button.addClass('mod-warning');
    }
    button.addEventListener('click', () => {
      void onClick();
    });
  }

  private createBadge(
    container: HTMLElement,
    label: string,
    tone: 'danger' | 'neutral' | 'success' | 'warning'
  ): void {
    container.createSpan({
      cls: `vulndash-badge vulndash-badge-${tone}`,
      text: label
    });
  }

  private createMetric(container: HTMLElement, label: string, value: string): void {
    const metric = container.createDiv({ cls: 'vulndash-sbom-metric' });
    metric.createDiv({ cls: 'vulndash-sbom-metric-label', text: label });
    metric.createDiv({ cls: 'vulndash-sbom-metric-value', text: value });
  }

  private createSummaryStat(container: HTMLElement, label: string, value: string): void {
    const stat = container.createDiv({ cls: 'vulndash-sbom-summary-stat' });
    stat.createDiv({ cls: 'vulndash-sbom-summary-value', text: value });
    stat.createDiv({ cls: 'vulndash-sbom-summary-label', text: label });
  }

  private renderSbomList(): void {
    if (!this.listHostEl) {
      return;
    }

    this.listHostEl.empty();
    const settings = this.plugin.getSettings();
    const filteredSboms = filterSbomsForWorkspace(settings.sboms, this.searchQuery);
    if (settings.sboms.length === 0) {
      this.renderEmptyState(this.listHostEl, {
        actionLabel: 'Add your first SBOM',
        body: 'No SBOMs are configured yet. Start by adding one and selecting a JSON file from your vault.',
        title: 'No SBOMs configured'
      }, async () => {
        await this.addSbomAndBrowse();
      });
      return;
    }

    if (filteredSboms.length === 0) {
      this.renderEmptyState(this.listHostEl, {
        body: 'Try a different label, path, namespace, or clear the current search.',
        title: 'No SBOMs match this search'
      });
      return;
    }

    const list = this.listHostEl.createDiv({ cls: 'vulndash-sbom-card-list' });
    for (const sbom of filteredSboms) {
      this.renderSbomCard(list, sbom);
    }
  }

  private renderEmptyState(
    container: HTMLElement,
    copy: {
      actionLabel?: string;
      body: string;
      title: string;
    },
    onAction?: () => Promise<void>
  ): void {
    const state = container.createDiv({ cls: 'vulndash-empty-state' });
    state.createEl('h3', { text: copy.title });
    state.createEl('p', { text: copy.body });

    if (copy.actionLabel && onAction) {
      const button = state.createEl('button', { text: copy.actionLabel });
      button.addClass('mod-cta');
      button.addEventListener('click', () => {
        void onAction();
      });
    }
  }

  private async addSbomAndBrowse(): Promise<void> {
    const createdSbom = await this.plugin.addSbom();
    this.onStateChanged?.();
    await this.renderAsync();
    this.openSbomFilePicker(createdSbom.id);
  }

  private openSbomFilePicker(sbomId: string): void {
    new SbomFileSuggestModal(this.app, (file) => {
      void this.attachSbomFile(sbomId, file.path);
    }).open();
  }

  private describeProjectNoteStatus(
    sbom: ImportedSbomConfig,
    status: ProjectNoteLookupResult | null
  ): string {
    if (!sbom.linkedProjectNotePath) {
      return 'No project note mapped yet. Matching findings from this SBOM will remain unmapped.';
    }

    if (!status) {
      return sbom.linkedProjectNotePath;
    }

    if (status.status === 'broken') {
      return `${status.displayName} is missing at ${status.notePath}. Repair the mapping to restore project correlation.`;
    }

    return `${status.displayName} (${status.notePath})`;
  }

  private getProjectNoteActionLabel(
    sbom: ImportedSbomConfig,
    status: ProjectNoteLookupResult | null
  ): string {
    if (!sbom.linkedProjectNotePath) {
      return 'Link Project Note';
    }

    return status?.status === 'broken' ? 'Repair Project Link' : 'Change Project Link';
  }

  private openProjectNotePicker(sbomId: string): void {
    new ProjectNoteSuggestModal(this.app, this.plugin.listProjectNotes(), (note) => {
      void (async () => {
        await saveSbomProjectNoteMapping(this.plugin, sbomId, note.notePath);
        new Notice(`Mapped ${note.displayName} to this SBOM.`);
        this.onStateChanged?.();
        await this.renderAsync();
      })();
    }).open();
  }

  private async attachSbomFile(sbomId: string, path: string): Promise<void> {
    const validation = await this.plugin.validateSbomPath(path);
    if (!validation.success) {
      await this.plugin.updateSbomConfig(sbomId, { lastError: validation.error });
      new Notice(validation.error);
      this.onStateChanged?.();
      await this.renderAsync();
      return;
    }

    await this.plugin.updateSbomConfig(sbomId, {
      lastError: '',
      path: validation.normalizedPath
    });

    const componentMessage = validation.componentCount === 0
      ? 'The file was attached, but no components were found yet.'
      : `${validation.componentCount} component${validation.componentCount === 1 ? '' : 's'} detected.`;
    new Notice(`Attached ${validation.normalizedPath}. ${componentMessage}`);
    this.onStateChanged?.();
    await this.renderAsync();
  }
}
