import { PluginSettingTab, App, Setting } from 'obsidian';
import type { VulnDashSettings, ColumnVisibility } from '../../application/services/types';
import VulnDashPlugin, { DEFAULT_SETTINGS } from '../../plugin';

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
    const settings = this.plugin.getSettings();
    containerEl.empty();

    containerEl.createEl('h2', { text: 'VulnDash Settings' });

    new Setting(containerEl)
      .setName('Poll on startup')
      .setDesc('Automatically start polling when the plugin loads.')
      .addToggle((toggle) => toggle.setValue(settings.pollOnStartup).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollOnStartup: value });
      })
      );

    new Setting(containerEl)
      .setName('Polling interval (seconds)')
      .addText((text) => text
        .setPlaceholder('60')
        .setValue(String(Math.floor(settings.pollingIntervalMs / 1000)))
        .onChange(async (value) => {
          const seconds = Number.parseInt(value, 10);
          if (Number.isNaN(seconds) || seconds < 30) return;
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollingIntervalMs: seconds * 1000 });
        })
      );

    new Setting(containerEl)
      .setName('Keyword filters (comma-separated)')
      .addText((text) => text.setValue(settings.keywordFilters.join(',')).onChange(async (value) => {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          keywordFilters: value.split(',').map((v) => v.trim()).filter(Boolean)
        });
      })
      );

    new Setting(containerEl)
      .setName('Treat keywords as regular expressions')
      .setDesc('Enables advanced keyword matching with case-insensitive regex patterns.')
      .addToggle((toggle) => toggle.setValue(settings.keywordRegexEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), keywordRegexEnabled: value });
      })
      );

    new Setting(containerEl)
      .setName('Product filters (comma-separated)')
      .addText((text) => text.setValue(settings.productFilters.join(',')).onChange(async (value) => {
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          productFilters: value.split(',').map((v) => v.trim()).filter(Boolean)
        });
      })
      );

    new Setting(containerEl)
      .setName('Minimum CVSS score')
      .addText((text) => text.setValue(String(settings.minCvssScore)).onChange(async (value) => {
        const score = Number.parseFloat(value);
        if (Number.isNaN(score) || score < 0 || score > 10) return;
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), minCvssScore: score });
      })
      );

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
      })
      );

    new Setting(containerEl)
      .setName('Desktop alerts for HIGH/CRITICAL')
      .setDesc('Use OS-level notifications for urgent vulnerabilities.')
      .addToggle((toggle) => toggle.setValue(settings.desktopAlertsHighOrCritical).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), desktopAlertsHighOrCritical: value });
      })
      );

    containerEl.createEl('h3', { text: 'Data Persistence & Performance' });

    new Setting(containerEl)
      .setName('Cache duration (seconds)')
      .setDesc('How long fetched vulnerability data remains in memory before refresh.')
      .addText((text) => text.setValue(String(Math.floor(settings.cacheDurationMs / 1000))).onChange(async (value) => {
        const seconds = Number.parseInt(value, 10);
        if (Number.isNaN(seconds) || seconds < 0) return;
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), cacheDurationMs: seconds * 1000 });
      })
      );

    new Setting(containerEl)
      .setName('Maximum results shown')
      .setDesc('Limits how many vulnerabilities are rendered in the dashboard.')
      .addText((text) => text.setValue(String(settings.maxResults)).onChange(async (value) => {
        const maxResults = Number.parseInt(value, 10);
        if (Number.isNaN(maxResults) || maxResults < 1) return;
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), maxResults });
      })
      );

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
      })
      );

    const columnDefs: Array<{ key: keyof ColumnVisibility; label: string; }> = [
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
        })
        );
    }


    containerEl.createEl('h3', { text: 'Sync Controls' });

    new Setting(containerEl)
      .setName('Max pages per sync')
      .addText((text) => text.setValue(String(settings.syncControls.maxPages)).onChange(async (value) => {
        const maxPages = Number.parseInt(value, 10);
        if (Number.isNaN(maxPages) || maxPages < 1) return;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, maxPages }
        });
      })
      );

    new Setting(containerEl)
      .setName('Max items per sync')
      .addText((text) => text.setValue(String(settings.syncControls.maxItems)).onChange(async (value) => {
        const maxItems = Number.parseInt(value, 10);
        if (Number.isNaN(maxItems) || maxItems < 1) return;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, maxItems }
        });
      })
      );

    new Setting(containerEl)
      .setName('Retry count')
      .addText((text) => text.setValue(String(settings.syncControls.retryCount)).onChange(async (value) => {
        const retryCount = Number.parseInt(value, 10);
        if (Number.isNaN(retryCount) || retryCount < 0) return;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, retryCount }
        });
      })
      );

    new Setting(containerEl)
      .setName('Backoff base (ms)')
      .addText((text) => text.setValue(String(settings.syncControls.backoffBaseMs)).onChange(async (value) => {
        const backoffBaseMs = Number.parseInt(value, 10);
        if (Number.isNaN(backoffBaseMs) || backoffBaseMs < 100) return;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, backoffBaseMs }
        });
      })
      );

    new Setting(containerEl)
      .setName('Overlap window (seconds)')
      .addText((text) => text.setValue(String(Math.floor(settings.syncControls.overlapWindowMs / 1000))).onChange(async (value) => {
        const seconds = Number.parseInt(value, 10);
        if (Number.isNaN(seconds) || seconds < 0) return;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, overlapWindowMs: seconds * 1000 }
        });
      })
      );

    new Setting(containerEl)
      .setName('Bootstrap lookback (hours)')
      .setDesc('Used when no prior source cursor exists.')
      .addText((text) => text.setValue(String(Math.floor(settings.syncControls.bootstrapLookbackMs / 3_600_000))).onChange(async (value) => {
        const hours = Number.parseInt(value, 10);
        if (Number.isNaN(hours) || hours < 1) return;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          syncControls: { ...this.plugin.getSettings().syncControls, bootstrapLookbackMs: hours * 3_600_000 }
        });
      })
      );

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
      })
      );

    new Setting(containerEl)
      .setName('Enable GitHub advisories feed')
      .addToggle((toggle) => toggle.setValue(getGitHubAdvisoryFeed(settings)?.enabled ?? false).onChange(async (value) => {
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          enableGithubFeed: value,
          feeds: current.feeds.map((feed) => (feed.id === 'github-advisories-default' ? { ...feed, enabled: value } : feed))
        });
      })
      );

    containerEl.createEl('h3', { text: 'Integration & Export' });

    new Setting(containerEl)
      .setName('Auto-note creation for CRITICAL')
      .addToggle((toggle) => toggle.setValue(settings.autoNoteCreationEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), autoNoteCreationEnabled: value });
      })
      );

    new Setting(containerEl)
      .setName('Auto-note folder')
      .addText((text) => text.setValue(settings.autoNoteFolder).onChange(async (value) => {
        const folder = value.trim();
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          autoNoteFolder: folder.length > 0 ? folder : DEFAULT_SETTINGS.autoNoteFolder
        });
      })
      );

    new Setting(containerEl)
      .setName('SBOM path (sbom.json)')
      .setDesc('Path inside your vault to a CycloneDX JSON file.')
      .addText((text) => text.setPlaceholder('reports/sbom.json').setValue(settings.sbomPath).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), sbomPath: value.trim() });
      })
      );

    new Setting(containerEl)
      .setName('Import Product Filters from SBOM')
      .setDesc('Loads component names from SBOM and replaces product filters.')
      .addButton((button) => {
        button.setButtonText('Import').onClick(() => {
          void this.plugin.importProductFiltersFromSbom();
        });
      });

    new Setting(containerEl)
      .setName('NVD API key')
      .setDesc('Optional. Stored encrypted; enter a new value to replace the saved key.')
      .addText((text) => {
        const hasExistingKey = Boolean(getNvdFeed(settings)?.apiKey ?? settings.nvdApiKey);
        text.inputEl.type = 'password';
        text.setPlaceholder(hasExistingKey ? 'Saved key configured' : 'No key configured').onChange(async (value) => {
          const nextKey = value.trim();
          if (!nextKey) return;
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            nvdApiKey: nextKey,
            feeds: current.feeds.map((feed) => (feed.id === 'nvd-default' && feed.type === 'nvd'
              ? { ...feed, apiKey: nextKey }
              : feed))
          });
        });
      })
      .addButton((button) => {
        button.setButtonText('Clear').onClick(async () => {
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            nvdApiKey: '',
            feeds: current.feeds.map((feed) => (feed.id === 'nvd-default' && feed.type === 'nvd'
              ? { ...feed, apiKey: '' }
              : feed))
          });
          this.display();
        });
      });

    new Setting(containerEl)
      .setName('GitHub token')
      .setDesc('Optional fine-grained token for higher API limits. Stored encrypted; enter a new value to replace the saved token.')
      .addText((text) => {
        const hasExistingToken = Boolean(getGitHubAdvisoryFeed(settings)?.token ?? settings.githubToken);
        text.inputEl.type = 'password';
        text.setPlaceholder(hasExistingToken ? 'Saved token configured' : 'No token configured').onChange(async (value) => {
          const nextToken = value.trim();
          if (!nextToken) return;
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            githubToken: nextToken,
            feeds: current.feeds.map((feed) => (feed.id === 'github-advisories-default'
              ? { ...feed, token: nextToken }
              : feed))
          });
        });
      })
      .addButton((button) => {
        button.setButtonText('Clear').onClick(async () => {
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            githubToken: '',
            feeds: current.feeds.map((feed) => (feed.id === 'github-advisories-default'
              ? { ...feed, token: '' }
              : feed))
          });
          this.display();
        });
      });
  }
}
