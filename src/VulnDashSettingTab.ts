import { PluginSettingTab, App, Setting } from 'obsidian';
import type { VulnDashSettings, ColumnVisibility } from './application/services/types';
import VulnDashPlugin, { DEFAULT_SETTINGS } from './plugin';

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

    containerEl.createEl('h3', { text: 'Advanced Filtering' });

    new Setting(containerEl)
      .setName('Enable NVD feed')
      .addToggle((toggle) => toggle.setValue(settings.enableNvdFeed).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), enableNvdFeed: value });
      })
      );

    new Setting(containerEl)
      .setName('Enable GitHub advisories feed')
      .addToggle((toggle) => toggle.setValue(settings.enableGithubFeed).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), enableGithubFeed: value });
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
      .setDesc('Optional. Key is stored in plugin data; avoid sharing vault config.')
      .addText((text) => {
        text.inputEl.type = 'password';
        text.setValue(settings.nvdApiKey).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), nvdApiKey: value.trim() });
        });
      });

    new Setting(containerEl)
      .setName('GitHub token')
      .setDesc('Optional fine-grained token for higher API limits. Never logged by plugin.')
      .addText((text) => {
        text.inputEl.type = 'password';
        text.setValue(settings.githubToken).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), githubToken: value.trim() });
        });
      });
  }
}
