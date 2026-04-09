import { App, Notice, PluginSettingTab, Setting } from 'obsidian';
import type { SbomFileChangeStatus } from '../../application/services/SbomImportService';
import type { ColumnVisibility, VulnDashSettings } from '../../application/services/types';
import VulnDashPlugin, { DEFAULT_SETTINGS } from '../../plugin';
import { SbomCompareModal } from './SbomCompareModal';
import { SbomComponentsModal } from './SbomComponentsModal';

const getNvdFeed = (settings: VulnDashSettings) =>
  settings.feeds.find((feed): feed is Extract<VulnDashSettings['feeds'][number], { type: 'nvd' }> =>
    feed.type === 'nvd' && feed.id === 'nvd-default');
const getGitHubAdvisoryFeed = (settings: VulnDashSettings) =>
  settings.feeds.find((feed): feed is Extract<VulnDashSettings['feeds'][number], { type: 'github_advisory' }> =>
    feed.type === 'github_advisory' && feed.id === 'github-advisories-default');

export class VulnDashSettingTab extends PluginSettingTab {
  private renderId = 0;

  public constructor(app: App, private readonly plugin: VulnDashPlugin) {
    super(app, plugin);
  }

  public display(): void {
    void this.displayAsync();
  }

  private async displayAsync(): Promise<void> {
    const activeRenderId = ++this.renderId;
    const { containerEl } = this;
    containerEl.empty();

    const settings = this.plugin.getSettings();
    const sbomStatuses = new Map(await Promise.all(settings.sboms.map(async (sbom) => (
      [sbom.id, await this.plugin.getSbomFileChangeStatus(sbom.id)] as const
    ))));

    if (activeRenderId !== this.renderId) {
      return;
    }

    containerEl.empty();
    this.renderGeneralSettings(containerEl, settings);
    this.renderSbomSettings(containerEl, settings, sbomStatuses);
    this.renderFeedSettings(containerEl, settings);
  }

  private renderGeneralSettings(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h2', { text: 'VulnDash Settings' });

    new Setting(containerEl)
      .setName('Poll on startup')
      .setDesc('Automatically start polling when the plugin loads.')
      .addToggle((toggle) => toggle.setValue(settings.pollOnStartup).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollOnStartup: value });
      }));

    new Setting(containerEl)
      .setName('Polling interval (seconds)')
      .addText((text) => text
        .setPlaceholder('60')
        .setValue(String(Math.floor(settings.pollingIntervalMs / 1000)))
        .onChange(async (value) => {
          const seconds = Number.parseInt(value, 10);
          if (Number.isNaN(seconds) || seconds < 30) {
            return;
          }

          await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollingIntervalMs: seconds * 1000 });
        }));

    new Setting(containerEl)
      .setName('Keyword filters (comma-separated)')
      .addText((text) => text.setValue(settings.keywordFilters.join(',')).onChange(async (value) => {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          keywordFilters: value.split(',').map((entry) => entry.trim()).filter(Boolean)
        });
      }));

    new Setting(containerEl)
      .setName('Treat keywords as regular expressions')
      .setDesc('Enables advanced keyword matching with case-insensitive regex patterns.')
      .addToggle((toggle) => toggle.setValue(settings.keywordRegexEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), keywordRegexEnabled: value });
      }));

    new Setting(containerEl)
      .setName('Manual product filters (comma-separated)')
      .setDesc('These filters are never overwritten by SBOM recomputation.')
      .addText((text) => text.setValue(settings.manualProductFilters.join(',')).onChange(async (value) => {
        await this.plugin.updateLocalSettings({
          ...this.plugin.getSettings(),
          manualProductFilters: value.split(',').map((entry) => entry.trim()).filter(Boolean)
        });
      }));

    containerEl.createEl('p', {
      text: settings.productFilters.length === 0
        ? 'Computed product filters: none.'
        : `Computed product filters (${settings.productFilters.length}): ${settings.productFilters.slice(0, 12).join(', ')}${settings.productFilters.length > 12 ? ' ...' : ''}`
    });

    new Setting(containerEl)
      .setName('Minimum CVSS score')
      .addText((text) => text.setValue(String(settings.minCvssScore)).onChange(async (value) => {
        const score = Number.parseFloat(value);
        if (Number.isNaN(score) || score < 0 || score > 10) {
          return;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), minCvssScore: score });
      }));

    new Setting(containerEl)
      .setName('Minimum severity')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ NONE: 'NONE', LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL' })
          .setValue(settings.minSeverity)
          .onChange(async (value) => {
            await this.plugin.updateSettings({
              ...this.plugin.getSettings(),
              minSeverity: value as VulnDashSettings['minSeverity']
            });
          });
      });

    containerEl.createEl('h3', { text: 'Notification & Alerting Controls' });

    new Setting(containerEl)
      .setName('System notifications')
      .setDesc('Show native Obsidian notices for newly matched vulnerabilities.')
      .addToggle((toggle) => toggle.setValue(settings.systemNotificationsEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), systemNotificationsEnabled: value });
      }));

    new Setting(containerEl)
      .setName('Desktop alerts for HIGH/CRITICAL')
      .setDesc('Use OS-level notifications for urgent vulnerabilities.')
      .addToggle((toggle) => toggle.setValue(settings.desktopAlertsHighOrCritical).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), desktopAlertsHighOrCritical: value });
      }));

    containerEl.createEl('h3', { text: 'Data Persistence & Performance' });

    new Setting(containerEl)
      .setName('Cache duration (seconds)')
      .setDesc('How long fetched vulnerability data remains in memory before refresh.')
      .addText((text) => text.setValue(String(Math.floor(settings.cacheDurationMs / 1000))).onChange(async (value) => {
        const seconds = Number.parseInt(value, 10);
        if (Number.isNaN(seconds) || seconds < 0) {
          return;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), cacheDurationMs: seconds * 1000 });
      }));

    new Setting(containerEl)
      .setName('Maximum results shown')
      .setDesc('Limits how many vulnerabilities are rendered in the dashboard.')
      .addText((text) => text.setValue(String(settings.maxResults)).onChange(async (value) => {
        const maxResults = Number.parseInt(value, 10);
        if (Number.isNaN(maxResults) || maxResults < 1) {
          return;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), maxResults });
      }));

    containerEl.createEl('h3', { text: 'UI & Dashboard Customization' });

    new Setting(containerEl)
      .setName('Default sort order')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ publishedAt: 'Published Date', cvssScore: 'CVSS Score' })
          .setValue(settings.defaultSortOrder)
          .onChange(async (value) => {
            await this.plugin.updateSettings({
              ...this.plugin.getSettings(),
              defaultSortOrder: value as VulnDashSettings['defaultSortOrder']
            });
          });
      });

    new Setting(containerEl)
      .setName('Color-coded severity')
      .setDesc('Applies severity CSS classes (for CRITICAL/HIGH rows).')
      .addToggle((toggle) => toggle.setValue(settings.colorCodedSeverity).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), colorCodedSeverity: value });
      }));

    const columnDefs: Array<{ key: keyof ColumnVisibility; label: string }> = [
      { key: 'id', label: 'ID' },
      { key: 'title', label: 'Title' },
      { key: 'source', label: 'Source' },
      { key: 'severity', label: 'Severity' },
      { key: 'cvssScore', label: 'CVSS' },
      { key: 'publishedAt', label: 'Published' }
    ];

    for (const columnDef of columnDefs) {
      new Setting(containerEl)
        .setName(`Show column: ${columnDef.label}`)
        .addToggle((toggle) => toggle.setValue(settings.columnVisibility[columnDef.key]).onChange(async (value) => {
          await this.plugin.updateSettings({
            ...this.plugin.getSettings(),
            columnVisibility: {
              ...this.plugin.getSettings().columnVisibility,
              [columnDef.key]: value
            }
          });
        }));
    }

    containerEl.createEl('h3', { text: 'Sync Controls' });

    new Setting(containerEl)
      .setName('Max pages per sync')
      .addText((text) => text.setValue(String(settings.syncControls.maxPages)).onChange(async (value) => {
        const maxPages = Number.parseInt(value, 10);
        if (Number.isNaN(maxPages) || maxPages < 1) {
          return;
        }

        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, maxPages }
        });
      }));

    new Setting(containerEl)
      .setName('Max items per sync')
      .addText((text) => text.setValue(String(settings.syncControls.maxItems)).onChange(async (value) => {
        const maxItems = Number.parseInt(value, 10);
        if (Number.isNaN(maxItems) || maxItems < 1) {
          return;
        }

        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, maxItems }
        });
      }));

    new Setting(containerEl)
      .setName('Retry count')
      .addText((text) => text.setValue(String(settings.syncControls.retryCount)).onChange(async (value) => {
        const retryCount = Number.parseInt(value, 10);
        if (Number.isNaN(retryCount) || retryCount < 0) {
          return;
        }

        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, retryCount }
        });
      }));

    new Setting(containerEl)
      .setName('Backoff base (ms)')
      .addText((text) => text.setValue(String(settings.syncControls.backoffBaseMs)).onChange(async (value) => {
        const backoffBaseMs = Number.parseInt(value, 10);
        if (Number.isNaN(backoffBaseMs) || backoffBaseMs < 100) {
          return;
        }

        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, backoffBaseMs }
        });
      }));

    new Setting(containerEl)
      .setName('Overlap window (seconds)')
      .addText((text) => text.setValue(String(Math.floor(settings.syncControls.overlapWindowMs / 1000))).onChange(async (value) => {
        const seconds = Number.parseInt(value, 10);
        if (Number.isNaN(seconds) || seconds < 0) {
          return;
        }

        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, overlapWindowMs: seconds * 1000 }
        });
      }));

    new Setting(containerEl)
      .setName('Bootstrap lookback (hours)')
      .setDesc('Used when no prior source cursor exists.')
      .addText((text) => text.setValue(String(Math.floor(settings.syncControls.bootstrapLookbackMs / 3_600_000))).onChange(async (value) => {
        const hours = Number.parseInt(value, 10);
        if (Number.isNaN(hours) || hours < 1) {
          return;
        }

        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, bootstrapLookbackMs: hours * 3_600_000 }
        });
      }));
  }

  private renderSbomSettings(
    containerEl: HTMLElement,
    settings: VulnDashSettings,
    sbomStatuses: Map<string, SbomFileChangeStatus>
  ): void {
    containerEl.createEl('h3', { text: 'SBOM Filter Management' });

    new Setting(containerEl)
      .setName('SBOM import mode')
      .setDesc('Replace uses imported filters only. Append keeps manual filters and imported filters together.')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ append: 'Append manual + imported', replace: 'Replace with imported only' })
          .setValue(settings.sbomImportMode)
          .onChange(async (value) => {
            await this.plugin.updateLocalSettings({
              ...this.plugin.getSettings(),
              sbomImportMode: value as VulnDashSettings['sbomImportMode']
            });
            this.display();
          });
      });

    new Setting(containerEl)
      .setName('Automatically apply imported SBOM filters')
      .setDesc('When disabled, imported SBOM components stay stored but do not affect computed product filters.')
      .addToggle((toggle) => toggle.setValue(settings.sbomAutoApplyFilters).onChange(async (value) => {
        await this.plugin.updateLocalSettings({
          ...this.plugin.getSettings(),
          sbomAutoApplyFilters: value
        });
        this.display();
      }));

    new Setting(containerEl)
      .setName('SBOM actions')
      .setDesc('Create SBOM entries and sync imported component inventories.')
      .addButton((button) => {
        button.setButtonText('Add SBOM').onClick(() => {
          void (async () => {
            await this.plugin.addSbom();
            this.display();
          })();
        });
      })
      .addButton((button) => {
        button.setButtonText('Sync All').onClick(() => {
          void (async () => {
            const result = await this.plugin.syncAllSboms();
            new Notice(`SBOM sync complete. ${result.succeeded}/${result.total} succeeded, ${result.failed} failed.`);
            this.display();
          })();
        });
      });

    if (settings.sboms.length === 0) {
      containerEl.createEl('p', { text: 'No SBOM entries configured yet.' });
      return;
    }

    for (const sbom of settings.sboms) {
      const sbomContainer = containerEl.createDiv({ cls: 'vulndash-sbom-entry' });
      const status = sbomStatuses.get(sbom.id);

      new Setting(sbomContainer)
        .setName(sbom.label || 'Unnamed SBOM')
        .setDesc(this.describeSbom(sbom, status))
        .addToggle((toggle) => toggle.setValue(sbom.enabled).onChange(async (value) => {
          await this.plugin.updateSbomConfig(sbom.id, { enabled: value });
          this.display();
        }))
        .addButton((button) => {
          button.setButtonText('Sync').onClick(() => {
            void (async () => {
              const result = await this.plugin.syncSbom(sbom.id);
              new Notice(result.message);
              this.display();
            })();
          });
        })
        .addButton((button) => {
          button.setButtonText('Components').onClick(() => {
            new SbomComponentsModal(this.plugin, sbom.id, () => this.display()).open();
          });
        })
        .addButton((button) => {
          button.setButtonText('Compare').setDisabled(settings.sboms.length < 2).onClick(() => {
            new SbomCompareModal(this.plugin, sbom.id).open();
          });
        })
        .addButton((button) => {
          button.setWarning().setButtonText('Remove').onClick(() => {
            void (async () => {
              await this.plugin.removeSbom(sbom.id);
              new Notice(`Removed ${sbom.label}.`);
              this.display();
            })();
          });
        });

      new Setting(sbomContainer)
        .setName('Label')
        .addText((text) => text.setPlaceholder('Production SBOM').setValue(sbom.label).onChange(async (value) => {
          await this.plugin.updateSbomConfig(sbom.id, { label: value.trim() || sbom.label });
        }));

      new Setting(sbomContainer)
        .setName('Path')
        .setDesc('Vault-relative path to the CycloneDX JSON file.')
        .addText((text) => text.setPlaceholder('reports/sbom.json').setValue(sbom.path).onChange(async (value) => {
          await this.plugin.updateSbomConfig(sbom.id, { path: value.trim() });
        }));

      new Setting(sbomContainer)
        .setName('Namespace')
        .setDesc('Stored as metadata only. It is not prefixed onto computed filters.')
        .addText((text) => text.setPlaceholder('team/platform').setValue(sbom.namespace).onChange(async (value) => {
          await this.plugin.updateSbomConfig(sbom.id, { namespace: value.trim() });
        }));

      if (sbom.lastImportError) {
        const errorBlock = sbomContainer.createDiv({ cls: 'vulndash-sbom-error' });
        errorBlock.createEl('strong', { text: 'Last import error: ' });
        errorBlock.appendText(sbom.lastImportError);
      }
    }
  }

  private renderFeedSettings(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'Advanced Filtering' });

    new Setting(containerEl)
      .setName('Enable NVD feed')
      .addToggle((toggle) => toggle.setValue(getNvdFeed(settings)?.enabled ?? false).onChange(async (value) => {
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          enableNvdFeed: value,
          feeds: current.feeds.map((feed) => (feed.id === 'nvd-default' ? { ...feed, enabled: value } : feed))
        });
      }));

    new Setting(containerEl)
      .setName('Enable GitHub advisories feed')
      .addToggle((toggle) => toggle.setValue(getGitHubAdvisoryFeed(settings)?.enabled ?? false).onChange(async (value) => {
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          enableGithubFeed: value,
          feeds: current.feeds.map((feed) => (feed.id === 'github-advisories-default' ? { ...feed, enabled: value } : feed))
        });
      }));

    containerEl.createEl('h3', { text: 'Integration & Export' });

    new Setting(containerEl)
      .setName('Auto-note creation for CRITICAL')
      .setDesc('Creates notes automatically for new CRITICAL vulnerabilities.')
      .addToggle((toggle) => toggle.setValue(settings.autoNoteCreationEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), autoNoteCreationEnabled: value });
      }));

    new Setting(containerEl)
      .setName('Auto-note creation for HIGH')
      .setDesc('Creates notes automatically for new HIGH vulnerabilities.')
      .addToggle((toggle) => toggle.setValue(settings.autoHighNoteCreationEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), autoHighNoteCreationEnabled: value });
      }));

    new Setting(containerEl)
      .setName('Auto-note folder')
      .addText((text) => text.setValue(settings.autoNoteFolder).onChange(async (value) => {
        const folder = value.trim();
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          autoNoteFolder: folder.length > 0 ? folder : DEFAULT_SETTINGS.autoNoteFolder
        });
      }));

    new Setting(containerEl)
      .setName('NVD API key')
      .setDesc('Optional. Key is stored in plugin data; avoid sharing vault config.')
      .addText((text) => {
        text.inputEl.type = 'password';
        text.setValue(getNvdFeed(settings)?.apiKey ?? settings.nvdApiKey).onChange(async (value) => {
          const nextKey = value.trim();
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            nvdApiKey: nextKey,
            feeds: current.feeds.map((feed) => (feed.id === 'nvd-default' && feed.type === 'nvd'
              ? { ...feed, apiKey: nextKey }
              : feed))
          });
        });
      });

    new Setting(containerEl)
      .setName('GitHub token')
      .setDesc('Optional fine-grained token for higher API limits. Never logged by plugin.')
      .addText((text) => {
        text.inputEl.type = 'password';
        text.setValue(getGitHubAdvisoryFeed(settings)?.token ?? settings.githubToken).onChange(async (value) => {
          const nextToken = value.trim();
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            githubToken: nextToken,
            feeds: current.feeds.map((feed) => (feed.id === 'github-advisories-default'
              ? { ...feed, token: nextToken }
              : feed))
          });
        });
      });
  }

  private describeSbom(
    sbom: VulnDashSettings['sboms'][number],
    status: SbomFileChangeStatus | undefined
  ): string {
    const parts = [
      `Path: ${sbom.path || 'not set'}`,
      `Namespace: ${sbom.namespace || 'none'}`,
      `Components: ${sbom.components.length}`,
      `Last import: ${sbom.lastImportedAt ? new Date(sbom.lastImportedAt).toLocaleString() : 'never'}`,
      `Hash: ${sbom.lastImportHash ? sbom.lastImportHash.slice(0, 12) : 'none'}`,
      `File status: ${this.describeFileStatus(status)}`
    ];

    return parts.join(' | ');
  }

  private describeFileStatus(status: SbomFileChangeStatus | undefined): string {
    if (!status) {
      return 'checking';
    }

    switch (status.status) {
      case 'changed':
        return 'changed since last import';
      case 'missing':
        return 'missing';
      case 'not-imported':
        return 'not imported yet';
      case 'unchanged':
        return 'unchanged';
      case 'error':
      default:
        return status.error ?? 'error';
    }
  }
}
