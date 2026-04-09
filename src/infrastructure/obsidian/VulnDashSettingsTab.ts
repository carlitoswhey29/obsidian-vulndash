import { App, PluginSettingTab, Setting } from 'obsidian';
import type { ColumnVisibility, VulnDashSettings } from '../../application/services/types';
import VulnDashPlugin, { DEFAULT_SETTINGS } from '../../plugin';
import { SbomManagerModal } from './SbomManagerModal';

const getNvdFeed = (settings: VulnDashSettings) =>
  settings.feeds.find((feed): feed is Extract<VulnDashSettings['feeds'][number], { type: 'nvd' }> =>
    feed.type === 'nvd' && feed.id === 'nvd-default');
const getGitHubAdvisoryFeed = (settings: VulnDashSettings) =>
  settings.feeds.find((feed): feed is Extract<VulnDashSettings['feeds'][number], { type: 'github_advisory' }> =>
    feed.type === 'github_advisory' && feed.id === 'github-advisories-default');

export class VulnDashSettingTab extends PluginSettingTab {
  public constructor(app: App, private readonly plugin: VulnDashPlugin) {
    super(app, plugin);
  }

  public display(): void {
    const { containerEl } = this;
    containerEl.empty();

    const settings = this.plugin.getSettings();
    this.renderGeneralSettings(containerEl, settings);
    this.renderSbomSettings(containerEl, settings);
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
      .setDesc('User-owned product filters. SBOM recompute never overwrites this list.')
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

    this.renderSyncControl(containerEl, 'Max pages per sync', String(settings.syncControls.maxPages), async (value) => {
      const maxPages = Number.parseInt(value, 10);
      if (!Number.isNaN(maxPages) && maxPages >= 1) {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, maxPages }
        });
      }
    });
    this.renderSyncControl(containerEl, 'Max items per sync', String(settings.syncControls.maxItems), async (value) => {
      const maxItems = Number.parseInt(value, 10);
      if (!Number.isNaN(maxItems) && maxItems >= 1) {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, maxItems }
        });
      }
    });
    this.renderSyncControl(containerEl, 'Retry count', String(settings.syncControls.retryCount), async (value) => {
      const retryCount = Number.parseInt(value, 10);
      if (!Number.isNaN(retryCount) && retryCount >= 0) {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, retryCount }
        });
      }
    });
    this.renderSyncControl(containerEl, 'Backoff base (ms)', String(settings.syncControls.backoffBaseMs), async (value) => {
      const backoffBaseMs = Number.parseInt(value, 10);
      if (!Number.isNaN(backoffBaseMs) && backoffBaseMs >= 100) {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, backoffBaseMs }
        });
      }
    });
    this.renderSyncControl(containerEl, 'Overlap window (seconds)', String(Math.floor(settings.syncControls.overlapWindowMs / 1000)), async (value) => {
      const seconds = Number.parseInt(value, 10);
      if (!Number.isNaN(seconds) && seconds >= 0) {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, overlapWindowMs: seconds * 1000 }
        });
      }
    });
    this.renderSyncControl(containerEl, 'Bootstrap lookback (hours)', String(Math.floor(settings.syncControls.bootstrapLookbackMs / 3_600_000)), async (value) => {
      const hours = Number.parseInt(value, 10);
      if (!Number.isNaN(hours) && hours >= 1) {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, bootstrapLookbackMs: hours * 3_600_000 }
        });
      }
    });
  }

  private renderSbomSettings(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'SBOM Management' });

    new Setting(containerEl)
      .setName('SBOM import mode')
      .setDesc('Replace uses SBOM-derived filters only. Append keeps manual filters and SBOM-derived filters together.')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ append: 'Append manual + SBOM', replace: 'Replace with SBOM only' })
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
      .setName('Manage SBOMs')
      .setDesc(`${settings.sboms.length} configured SBOM${settings.sboms.length === 1 ? '' : 's'}. Runtime component data is loaded outside settings storage.`)
      .addButton((button) => {
        button.setButtonText('Manage SBOMs').onClick(() => {
          new SbomManagerModal(this.plugin, () => this.display()).open();
        });
      });
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

  private renderSyncControl(
    containerEl: HTMLElement,
    name: string,
    value: string,
    onChange: (value: string) => Promise<void>
  ): void {
    new Setting(containerEl)
      .setName(name)
      .addText((text) => text.setValue(value).onChange(async (nextValue) => {
        await onChange(nextValue);
      }));
  }
}
