import { App, PluginSettingTab, Setting, TextComponent } from 'obsidian';
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

    const pollingIntervalSetting = new Setting(containerEl)
      .setName('Polling interval (seconds)');
    this.bindBlurPersistedText(pollingIntervalSetting, {
      initialValue: String(Math.floor(settings.pollingIntervalMs / 1000)),
      placeholder: '60',
      persist: async (value, committedValue) => {
        const seconds = Number.parseInt(value, 10);
        if (Number.isNaN(seconds) || seconds < 30) {
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollingIntervalMs: seconds * 1000 });
        return String(seconds);
      }
    });

    const keywordFiltersSetting = new Setting(containerEl)
      .setName('Keyword filters (comma-separated)');
    this.bindBlurPersistedText(keywordFiltersSetting, {
      initialValue: settings.keywordFilters.join(','),
      persist: async (value) => {
        const keywordFilters = value.split(',').map((entry) => entry.trim()).filter(Boolean);
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          keywordFilters
        });
        return keywordFilters.join(',');
      }
    });

    new Setting(containerEl)
      .setName('Treat keywords as regular expressions')
      .setDesc('Enables advanced keyword matching with case-insensitive regex patterns.')
      .addToggle((toggle) => toggle.setValue(settings.keywordRegexEnabled).onChange(async (value) => {
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), keywordRegexEnabled: value });
      }));

    const manualFiltersSetting = new Setting(containerEl)
      .setName('Manual product filters (comma-separated)')
      .setDesc('User-owned product filters. SBOM recompute never overwrites this list.');
    this.bindBlurPersistedText(manualFiltersSetting, {
      initialValue: settings.manualProductFilters.join(','),
      persist: async (value) => {
        const manualProductFilters = value.split(',').map((entry) => entry.trim()).filter(Boolean);
        await this.plugin.updateLocalSettings({
          ...this.plugin.getSettings(),
          manualProductFilters
        });
        return manualProductFilters.join(',');
      }
    });

    containerEl.createEl('p', {
      text: settings.productFilters.length === 0
        ? 'Computed product filters: none.'
        : `Computed product filters (${settings.productFilters.length}): ${settings.productFilters.slice(0, 12).join(', ')}${settings.productFilters.length > 12 ? ' ...' : ''}`
    });

    const minCvssSetting = new Setting(containerEl)
      .setName('Minimum CVSS score');
    this.bindBlurPersistedText(minCvssSetting, {
      initialValue: String(settings.minCvssScore),
      persist: async (value, committedValue) => {
        const score = Number.parseFloat(value);
        if (Number.isNaN(score) || score < 0 || score > 10) {
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), minCvssScore: score });
        return String(score);
      }
    });

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

    const cacheDurationSetting = new Setting(containerEl)
      .setName('Cache duration (seconds)')
      .setDesc('How long fetched vulnerability data remains in memory before refresh.');
    this.bindBlurPersistedText(cacheDurationSetting, {
      initialValue: String(Math.floor(settings.cacheDurationMs / 1000)),
      persist: async (value, committedValue) => {
        const seconds = Number.parseInt(value, 10);
        if (Number.isNaN(seconds) || seconds < 0) {
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), cacheDurationMs: seconds * 1000 });
        return String(seconds);
      }
    });

    const maxResultsSetting = new Setting(containerEl)
      .setName('Maximum results shown')
      .setDesc('Limits how many vulnerabilities are rendered in the dashboard.');
    this.bindBlurPersistedText(maxResultsSetting, {
      initialValue: String(settings.maxResults),
      persist: async (value, committedValue) => {
        const maxResults = Number.parseInt(value, 10);
        if (Number.isNaN(maxResults) || maxResults < 1) {
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), maxResults });
        return String(maxResults);
      }
    });

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

    this.renderSyncControl(containerEl, 'Max pages per sync', String(settings.syncControls.maxPages), async (value, committedValue) => {
      const maxPages = Number.parseInt(value, 10);
      if (Number.isNaN(maxPages) || maxPages < 1) {
        return committedValue;
      }

      await this.plugin.updateSettings({
        ...this.plugin.getSettings(),
        syncControls: { ...this.plugin.getSettings().syncControls, maxPages }
      });
      return String(maxPages);
    });
    this.renderSyncControl(containerEl, 'Max items per sync', String(settings.syncControls.maxItems), async (value, committedValue) => {
      const maxItems = Number.parseInt(value, 10);
      if (Number.isNaN(maxItems) || maxItems < 1) {
        return committedValue;
      }

      await this.plugin.updateSettings({
        ...this.plugin.getSettings(),
        syncControls: { ...this.plugin.getSettings().syncControls, maxItems }
      });
      return String(maxItems);
    });
    this.renderSyncControl(containerEl, 'Retry count', String(settings.syncControls.retryCount), async (value, committedValue) => {
      const retryCount = Number.parseInt(value, 10);
      if (Number.isNaN(retryCount) || retryCount < 0) {
        return committedValue;
      }

      await this.plugin.updateSettings({
        ...this.plugin.getSettings(),
        syncControls: { ...this.plugin.getSettings().syncControls, retryCount }
      });
      return String(retryCount);
    });
    this.renderSyncControl(containerEl, 'Backoff base (ms)', String(settings.syncControls.backoffBaseMs), async (value, committedValue) => {
      const backoffBaseMs = Number.parseInt(value, 10);
      if (Number.isNaN(backoffBaseMs) || backoffBaseMs < 100) {
        return committedValue;
      }

      await this.plugin.updateSettings({
        ...this.plugin.getSettings(),
        syncControls: { ...this.plugin.getSettings().syncControls, backoffBaseMs }
      });
      return String(backoffBaseMs);
    });
    this.renderSyncControl(containerEl, 'Overlap window (seconds)', String(Math.floor(settings.syncControls.overlapWindowMs / 1000)), async (value, committedValue) => {
      const seconds = Number.parseInt(value, 10);
      if (Number.isNaN(seconds) || seconds < 0) {
        return committedValue;
      }

      await this.plugin.updateSettings({
        ...this.plugin.getSettings(),
        syncControls: { ...this.plugin.getSettings().syncControls, overlapWindowMs: seconds * 1000 }
      });
      return String(seconds);
    });
    this.renderSyncControl(containerEl, 'Bootstrap lookback (hours)', String(Math.floor(settings.syncControls.bootstrapLookbackMs / 3_600_000)), async (value, committedValue) => {
      const hours = Number.parseInt(value, 10);
      if (Number.isNaN(hours) || hours < 1) {
        return committedValue;
      }

      await this.plugin.updateSettings({
        ...this.plugin.getSettings(),
        syncControls: { ...this.plugin.getSettings().syncControls, bootstrapLookbackMs: hours * 3_600_000 }
      });
      return String(hours);
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

    const autoNoteFolderSetting = new Setting(containerEl)
      .setName('Auto-note folder');
    this.bindBlurPersistedText(autoNoteFolderSetting, {
      initialValue: settings.autoNoteFolder,
      persist: async (value) => {
        const folder = value.trim();
        const nextFolder = folder.length > 0 ? folder : DEFAULT_SETTINGS.autoNoteFolder;
        await this.plugin.updateSettings({
          ...this.plugin.getSettings(),
          autoNoteFolder: nextFolder
        });
        return nextFolder;
      }
    });

    const nvdKeySetting = new Setting(containerEl)
      .setName('NVD API key')
      .setDesc('Optional. Key is stored in plugin data; avoid sharing vault config.');
    this.bindBlurPersistedText(nvdKeySetting, {
      initialValue: getNvdFeed(settings)?.apiKey ?? settings.nvdApiKey,
      inputType: 'password',
      persist: async (value) => {
        const nextKey = value.trim();
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          nvdApiKey: nextKey,
          feeds: current.feeds.map((feed) => (feed.id === 'nvd-default' && feed.type === 'nvd'
            ? { ...feed, apiKey: nextKey }
            : feed))
        });
        return nextKey;
      }
    });

    const githubTokenSetting = new Setting(containerEl)
      .setName('GitHub token')
      .setDesc('Optional fine-grained token for higher API limits. Never logged by plugin.');
    this.bindBlurPersistedText(githubTokenSetting, {
      initialValue: getGitHubAdvisoryFeed(settings)?.token ?? settings.githubToken,
      inputType: 'password',
      persist: async (value) => {
        const nextToken = value.trim();
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          githubToken: nextToken,
          feeds: current.feeds.map((feed) => (feed.id === 'github-advisories-default'
            ? { ...feed, token: nextToken }
            : feed))
        });
        return nextToken;
      }
    });
  }

  private renderSyncControl(
    containerEl: HTMLElement,
    name: string,
    value: string,
    persist: (value: string, committedValue: string) => Promise<string>
  ): void {
    const setting = new Setting(containerEl).setName(name);
    this.bindBlurPersistedText(setting, {
      initialValue: value,
      persist
    });
  }

  private bindBlurPersistedText(
    setting: Setting,
    options: {
      initialValue: string;
      inputType?: string;
      persist: (value: string, committedValue: string) => Promise<string>;
      placeholder?: string;
    }
  ): void {
    let draftValue = options.initialValue;
    let committedValue = options.initialValue;

    setting.addText((text) => {
      if (options.placeholder) {
        text.setPlaceholder(options.placeholder);
      }
      if (options.inputType) {
        text.inputEl.type = options.inputType;
      }

      text.setValue(options.initialValue);
      text.onChange((value) => {
        draftValue = value;
      });
      text.inputEl.addEventListener('blur', () => {
        if (draftValue === committedValue) {
          return;
        }

        void this.persistTextValue(text, async () => {
          const nextValue = await options.persist(draftValue, committedValue);
          draftValue = nextValue;
          committedValue = nextValue;
          if (text.inputEl.value !== nextValue) {
            text.setValue(nextValue);
          }
        });
      });
    });
  }

  private async persistTextValue(text: TextComponent, save: () => Promise<void>): Promise<void> {
    text.inputEl.classList.add('vulndash-input-saving');
    try {
      await save();
      text.inputEl.classList.add('vulndash-input-saved');
      window.setTimeout(() => {
        text.inputEl.classList.remove('vulndash-input-saved');
      }, 600);
    } finally {
      text.inputEl.classList.remove('vulndash-input-saving');
    }
  }
}
