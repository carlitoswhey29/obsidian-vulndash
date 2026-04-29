import { App, Notice, PluginSettingTab, Setting, TextComponent } from 'obsidian';
import {
  DEFAULT_OSV_ENDPOINT_URL,
  DEFAULT_OSV_MAX_BATCH_SIZE,
  DEFAULT_SETTINGS,
  MAX_CONFIGURABLE_OSV_BATCH_SIZE,
  parseConfiguredOsvEndpointUrl,
  parseConfiguredOsvMaxBatchSize
} from '../../application/use-cases/DefaultSettings';
import type { ColumnVisibility, ImportedSbomConfig, VulnDashSettings } from '../../application/use-cases/types';
import { summarizeSbomWorkspace } from '../../application/use-cases/SbomWorkspaceService';
import { BUILT_IN_FEEDS, FEED_TYPES } from '../../domain/feeds/FeedTypes';
import { TRIAGE_STATES, formatTriageStateLabel } from '../../domain/triage/TriageState';
import { ProductFiltersModal } from '../modals/ProductFiltersModal';
import { SbomManagerModal } from '../modals/SbomManagerModal';
import VulnDashPlugin from '../plugin/VulnDashPlugin';

interface ComputedProductFiltersSummaryData {
  activeFilterCount: number;
  contributingSbomCount: number;
  enabledSbomCount: number;
  filters: string[];
  groups: Array<{
    filters: string[];
    label: string;
    sbomId: string;
  }>;
  manualFilterCount: number;
}

type PersistTextValue = (value: string, committedValue: string) => Promise<string>;

type NvdFeed = Extract<VulnDashSettings['feeds'][number], { type: typeof FEED_TYPES.NVD }>;
type GitHubAdvisoryFeed = Extract<VulnDashSettings['feeds'][number], { type: typeof FEED_TYPES.GITHUB_ADVISORY }>;
type OsvFeed = Extract<VulnDashSettings['feeds'][number], { type: typeof FEED_TYPES.OSV }>;

const PRODUCT_FILTER_PREVIEW_LIMIT = 5;
const BUTTON_FEEDBACK_MS = 1_200;
const SAVED_FEEDBACK_MS = 600;

const getNvdFeed = (settings: VulnDashSettings): NvdFeed | undefined =>
  settings.feeds.find((feed): feed is NvdFeed =>
    feed.type === FEED_TYPES.NVD && feed.id === BUILT_IN_FEEDS.NVD.id);

const getGitHubAdvisoryFeed = (settings: VulnDashSettings): GitHubAdvisoryFeed | undefined =>
  settings.feeds.find((feed): feed is GitHubAdvisoryFeed =>
    feed.type === FEED_TYPES.GITHUB_ADVISORY && feed.id === BUILT_IN_FEEDS.GITHUB_ADVISORY.id);

const getOsvFeed = (settings: VulnDashSettings): OsvFeed | undefined =>
  settings.feeds.find((feed): feed is OsvFeed =>
    feed.type === FEED_TYPES.OSV && feed.id === BUILT_IN_FEEDS.OSV.id);

const parseCommaSeparatedValues = (value: string): string[] =>
  value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);

export class VulnDashSettingTab extends PluginSettingTab {
  private computedProductFiltersRenderId = 0;

  public constructor(app: App, private readonly plugin: VulnDashPlugin) {
    super(app, plugin);
  }

  public display(): void {
    const { containerEl } = this;
    containerEl.empty();

    const settings = this.plugin.getSettings();
    containerEl.createEl('h2', { text: 'VulnDash Settings' });

    this.renderFeedsAndCredentials(containerEl, settings);
    this.renderFilteringAndSboms(containerEl, settings);
    this.renderDisplayAndNotifications(containerEl, settings);
    this.renderDailyBriefing(containerEl, settings);
    this.renderAdvancedSyncAndPerformance(containerEl, settings);
  }

  private renderFeedsAndCredentials(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'Vulnerability Feeds & Credentials' });

   // NVD Settings
    new Setting(containerEl)
      .setName('Enable NVD feed')
      .addToggle((toggle) => toggle.setValue(getNvdFeed(settings)?.enabled ?? false).onChange(async (value) => {
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          enableNvdFeed: value,
          feeds: current.feeds.map((feed) => (feed.id === BUILT_IN_FEEDS.NVD.id && feed.type === FEED_TYPES.NVD ? { ...feed, enabled: value } : feed))
        });
      }));

    new Setting(containerEl)
      .setName('NVD date filter field')
      .setDesc('Controls whether NVD sync windows use last modified timestamps or published timestamps.')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ modified: 'Modified Time', published: 'Published Time' })
          .setValue(getNvdFeed(settings)?.dateFilterType ?? 'modified')
          .onChange(async (value) => {
            const current = this.plugin.getSettings();
            await this.plugin.updateSettings({
              ...current,
              feeds: current.feeds.map((feed) => (feed.id === BUILT_IN_FEEDS.NVD.id && feed.type === FEED_TYPES.NVD
                ? { ...feed, dateFilterType: value as 'modified' | 'published' }
                : feed))
            });
          });
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
          feeds: current.feeds.map((feed) => (feed.id === BUILT_IN_FEEDS.NVD.id && feed.type === FEED_TYPES.NVD
            ? { ...feed, apiKey: nextKey }
            : feed))
        });
        return nextKey;
      }
    });

    // GitHub Settings
    new Setting(containerEl)
      .setName('Enable GitHub advisories feed')
      .addToggle((toggle) => toggle.setValue(getGitHubAdvisoryFeed(settings)?.enabled ?? false).onChange(async (value) => {
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          enableGithubFeed: value,
          feeds: current.feeds.map((feed) => (feed.id === BUILT_IN_FEEDS.GITHUB_ADVISORY.id && feed.type === FEED_TYPES.GITHUB_ADVISORY ? { ...feed, enabled: value } : feed))
        });
      }));

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
          feeds: current.feeds.map((feed) => (feed.id === BUILT_IN_FEEDS.GITHUB_ADVISORY.id && feed.type === FEED_TYPES.GITHUB_ADVISORY
            ? { ...feed, token: nextToken }
            : feed))
        });
        return nextToken;
      }
    });

    new Setting(containerEl)
      .setName('Enable OSV feed')
      .addToggle((toggle) => toggle
        .setValue(getOsvFeed(settings)?.enabled ?? false)
        .onChange(async (enabled) => {
          await this.updateBuiltInFeed(BUILT_IN_FEEDS.OSV.id, FEED_TYPES.OSV, { enabled });
        }));

    const osvEndpointSetting = new Setting(containerEl)
      .setName('OSV batch endpoint URL')
      .setDesc('Full HTTP(S) querybatch endpoint. Leave blank to use the public OSV API default.');
    this.bindBlurPersistedText(osvEndpointSetting, {
      initialValue: getOsvFeed(settings)?.osvEndpointUrl ?? DEFAULT_OSV_ENDPOINT_URL,
      persist: async (value, committedValue) => {
        const trimmed = value.trim();
        const endpointUrl = trimmed.length === 0
          ? DEFAULT_OSV_ENDPOINT_URL
          : parseConfiguredOsvEndpointUrl(trimmed);

        if (!endpointUrl) {
          new Notice('OSV endpoint must be a valid absolute HTTP(S) URL.');
          return committedValue;
        }

        await this.updateBuiltInFeed(BUILT_IN_FEEDS.OSV.id, FEED_TYPES.OSV, { osvEndpointUrl: endpointUrl });
        return endpointUrl;
      }
    });

    const osvBatchSizeSetting = new Setting(containerEl)
      .setName('OSV max batch size')
      .setDesc(`Queries per OSV batch request. Leave blank to reset to ${DEFAULT_OSV_MAX_BATCH_SIZE}.`);
    this.bindBlurPersistedText(osvBatchSizeSetting, {
      initialValue: String(getOsvFeed(settings)?.osvMaxBatchSize ?? DEFAULT_OSV_MAX_BATCH_SIZE),
      persist: async (value, committedValue) => {
        const trimmed = value.trim();
        const batchSize = trimmed.length === 0
          ? DEFAULT_OSV_MAX_BATCH_SIZE
          : parseConfiguredOsvMaxBatchSize(trimmed);

        if (batchSize === null) {
          new Notice(`OSV max batch size must be an integer between 1 and ${MAX_CONFIGURABLE_OSV_BATCH_SIZE}.`);
          return committedValue;
        }

        await this.updateBuiltInFeed(BUILT_IN_FEEDS.OSV.id, FEED_TYPES.OSV, { osvMaxBatchSize: batchSize });
        return String(batchSize);
      }
    });
  }

  private renderFilteringAndSboms(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'Filtering & SBOM Integration' });

    new Setting(containerEl)
      .setName('Minimum severity')
      .setDesc('Ignore vulnerabilities below this severity level.')
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

    const minCvssSetting = new Setting(containerEl)
      .setName('Minimum CVSS score')
      .setDesc('Accepted range: 0.0 through 10.0.');
    this.bindBlurPersistedText(minCvssSetting, {
      initialValue: String(settings.minCvssScore),
      persist: async (value, committedValue) => {
        const score = Number.parseFloat(value.trim());
        if (!Number.isFinite(score) || score < 0 || score > 10) {
          new Notice('Minimum CVSS score must be between 0 and 10.');
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), minCvssScore: score });
        return String(score);
      }
    });

    const keywordFiltersSetting = new Setting(containerEl)
      .setName('Keyword filters (comma-separated)')
      .setDesc('Match vulnerabilities containing specific terms in their details.');
    this.bindBlurPersistedText(keywordFiltersSetting, {
      initialValue: settings.keywordFilters.join(','),
      persist: async (value) => {
        const keywordFilters = parseCommaSeparatedValues(value);
        await this.plugin.updateSettings({ ...this.plugin.getSettings(), keywordFilters });
        return keywordFilters.join(',');
      }
    });

    new Setting(containerEl)
      .setName('Treat keywords as regular expressions')
      .setDesc('Enables advanced keyword matching with case-insensitive regex patterns.')
      .addToggle((toggle) => toggle
        .setValue(settings.keywordRegexEnabled)
        .onChange(async (keywordRegexEnabled) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), keywordRegexEnabled });
        }));

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

    const summarySetting = new Setting(containerEl)
      .setName('SBOM workspace')
      .setDesc(this.formatSbomSummaryText(summarizeSbomWorkspace(settings.sboms)))
      .addButton((button) => {
        button
          .setCta()
          .setButtonText('Manage SBOMs')
          .onClick(() => {
            new SbomManagerModal(this.plugin, () => this.display()).open();
          });
      });
    void this.refreshSbomSummary(summarySetting);

    const manualFiltersSetting = new Setting(containerEl)
      .setName('Manual product filters (comma-separated)')
      .setDesc('User-owned product filters. SBOM recompute never overwrites this list.');
    this.bindBlurPersistedText(manualFiltersSetting, {
      initialValue: settings.manualProductFilters.join(','),
      persist: async (value) => {
        const manualProductFilters = this.normalizeProductFilters(parseCommaSeparatedValues(value));
        await this.plugin.updateLocalSettings({
          ...this.plugin.getSettings(),
          manualProductFilters
        });
        return manualProductFilters.join(',');
      }
    });

    this.renderComputedProductFiltersSummary(containerEl);
  }

  private renderDisplayAndNotifications(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'Dashboard Display & Notifications' });

    new Setting(containerEl)
      .setName('System notifications')
      .setDesc('Show native Obsidian notices for newly matched vulnerabilities.')
      .addToggle((toggle) => toggle
        .setValue(settings.systemNotificationsEnabled)
        .onChange(async (systemNotificationsEnabled) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), systemNotificationsEnabled });
        }));

    new Setting(containerEl)
      .setName('Desktop alerts for HIGH/CRITICAL')
      .setDesc('Use OS-level notifications for urgent vulnerabilities.')
      .addToggle((toggle) => toggle
        .setValue(settings.desktopAlertsHighOrCritical)
        .onChange(async (desktopAlertsHighOrCritical) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), desktopAlertsHighOrCritical });
        }));

    const maxResultsSetting = new Setting(containerEl)
      .setName('Maximum results shown')
      .setDesc('Limits how many vulnerabilities are rendered in the dashboard view.');
    this.bindBlurPersistedText(maxResultsSetting, {
      initialValue: String(settings.maxResults),
      persist: async (value, committedValue) => {
        const maxResults = Number.parseInt(value.trim(), 10);
        if (!Number.isFinite(maxResults) || maxResults < 1) {
          new Notice('Maximum results must be at least 1.');
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), maxResults });
        return String(maxResults);
      }
    });

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
      .setName('Dashboard date field')
      .setDesc('Controls whether the dashboard date range uses modified time or published time.')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ modified: 'Modified Time', published: 'Published Time' })
          .setValue(settings.dashboardDateField)
          .onChange(async (value) => {
            await this.plugin.updateSettings({
              ...this.plugin.getSettings(),
              dashboardDateField: value as VulnDashSettings['dashboardDateField']
            });
          });
      });

    new Setting(containerEl)
      .setName('Color-coded severity')
      .setDesc('Applies severity CSS classes for severity-aware rows.')
      .addToggle((toggle) => toggle
        .setValue(settings.colorCodedSeverity)
        .onChange(async (colorCodedSeverity) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), colorCodedSeverity });
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
        .addToggle((toggle) => toggle
          .setValue(settings.columnVisibility[columnDef.key])
          .onChange(async (value) => {
            const current = this.plugin.getSettings();
            await this.plugin.updateSettings({
              ...current,
              columnVisibility: {
                ...current.columnVisibility,
                [columnDef.key]: value
              }
            });
          }));
    }
  }

  private renderDailyBriefing(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'Daily Threat Briefing' });

    const dailyRollupFolderSetting = new Setting(containerEl)
      .setName('Briefing folder')
      .setDesc('Vault-relative folder where daily briefing notes are written.');
    this.bindBlurPersistedText(dailyRollupFolderSetting, {
      initialValue: settings.dailyRollup.folderPath,
      persist: async (value) => {
        const folder = value.trim();
        const folderPath = folder.length > 0 ? folder : DEFAULT_SETTINGS.dailyRollup.folderPath;
        const current = this.plugin.getSettings();
        await this.plugin.updateSettings({
          ...current,
          dailyRollup: {
            ...current.dailyRollup,
            folderPath
          }
        });
        return folderPath;
      }
    });

    new Setting(containerEl)
      .setName('Severity threshold')
      .setDesc('Only findings at or above this severity are included in the daily briefing.')
      .addDropdown((dropdown) => {
        dropdown
          .addOptions({ LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL' })
          .setValue(settings.dailyRollup.severityThreshold)
          .onChange(async (value) => {
            const current = this.plugin.getSettings();
            await this.plugin.updateSettings({
              ...current,
              dailyRollup: {
                ...current.dailyRollup,
                severityThreshold: value as VulnDashSettings['dailyRollup']['severityThreshold']
              }
            });
          });
      });

    new Setting(containerEl)
      .setName('Include unmapped findings')
      .setDesc('Keeps findings without a mapped project note in the dedicated Unmapped Findings section.')
      .addToggle((toggle) => toggle
        .setValue(settings.dailyRollup.includeUnmappedFindings)
        .onChange(async (includeUnmappedFindings) => {
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            dailyRollup: {
              ...current.dailyRollup,
              includeUnmappedFindings
            }
          });
        }));

    new Setting(containerEl)
      .setName('Auto-generate on first sync of day')
      .setDesc('Writes or refreshes the daily briefing automatically after the first successful sync for the current day.')
      .addToggle((toggle) => toggle
        .setValue(settings.dailyRollup.autoGenerateOnFirstSyncOfDay)
        .onChange(async (autoGenerateOnFirstSyncOfDay) => {
          const current = this.plugin.getSettings();
          await this.plugin.updateSettings({
            ...current,
            dailyRollup: {
              ...current.dailyRollup,
              autoGenerateOnFirstSyncOfDay
            }
          });
        }));

    for (const triageState of TRIAGE_STATES) {
      new Setting(containerEl)
        .setName(`Exclude triage state: ${formatTriageStateLabel(triageState)}`)
        .addToggle((toggle) => toggle
          .setValue(settings.dailyRollup.excludedTriageStates.includes(triageState))
          .onChange(async (enabled) => {
            const current = this.plugin.getSettings();
            const excludedTriageStates = enabled
              ? Array.from(new Set([...current.dailyRollup.excludedTriageStates, triageState]))
              : current.dailyRollup.excludedTriageStates.filter((state) => state !== triageState);

            await this.plugin.updateSettings({
              ...current,
              dailyRollup: {
                ...current.dailyRollup,
                excludedTriageStates
              }
            });
          }));
    }
  }

  private renderAdvancedSyncAndPerformance(containerEl: HTMLElement, settings: VulnDashSettings): void {
    containerEl.createEl('h3', { text: 'Advanced Sync & Performance' });

    new Setting(containerEl)
      .setName('Poll on startup')
      .setDesc('Automatically start polling when the plugin loads.')
      .addToggle((toggle) => toggle
        .setValue(settings.pollOnStartup)
        .onChange(async (pollOnStartup) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollOnStartup });
        }));

    const pollingIntervalSetting = new Setting(containerEl)
      .setName('Polling interval (seconds)')
      .setDesc('Minimum accepted value: 30 seconds.');
    this.bindBlurPersistedText(pollingIntervalSetting, {
      initialValue: String(Math.floor(settings.pollingIntervalMs / 1_000)),
      placeholder: '60',
      persist: async (value, committedValue) => {
        const seconds = Number.parseInt(value.trim(), 10);
        if (!Number.isFinite(seconds) || seconds < 30) {
          new Notice('Polling interval must be at least 30 seconds.');
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), pollingIntervalMs: seconds * 1_000 });
        return String(seconds);
      }
    });

    const cacheDurationSetting = new Setting(containerEl)
      .setName('Cache duration (seconds)')
      .setDesc('How long fetched vulnerability data remains in memory before refresh.');
    this.bindBlurPersistedText(cacheDurationSetting, {
      initialValue: String(Math.floor(settings.cacheDurationMs / 1_000)),
      persist: async (value, committedValue) => {
        const seconds = Number.parseInt(value.trim(), 10);
        if (!Number.isFinite(seconds) || seconds < 0) {
          new Notice('Cache duration must be 0 seconds or greater.');
          return committedValue;
        }

        await this.plugin.updateSettings({ ...this.plugin.getSettings(), cacheDurationMs: seconds * 1_000 });
        return String(seconds);
      }
    });

    this.renderSyncControl(containerEl, 'Max pages per sync', String(settings.syncControls.maxPages), async (value, committedValue) => {
      const maxPages = Number.parseInt(value.trim(), 10);
      if (!Number.isFinite(maxPages) || maxPages < 1) {
        new Notice('Max pages per sync must be at least 1.');
        return committedValue;
      }

      await this.updateSyncControls({ maxPages });
      return String(maxPages);
    });

    this.renderSyncControl(containerEl, 'Max items per sync', String(settings.syncControls.maxItems), async (value, committedValue) => {
      const maxItems = Number.parseInt(value.trim(), 10);
      if (!Number.isFinite(maxItems) || maxItems < 1) {
        new Notice('Max items per sync must be at least 1.');
        return committedValue;
      }

      await this.updateSyncControls({ maxItems });
      return String(maxItems);
    });

    this.renderSyncControl(containerEl, 'Retry count', String(settings.syncControls.retryCount), async (value, committedValue) => {
      const retryCount = Number.parseInt(value.trim(), 10);
      if (!Number.isFinite(retryCount) || retryCount < 0) {
        new Notice('Retry count must be 0 or greater.');
        return committedValue;
      }

      await this.updateSyncControls({ retryCount });
      return String(retryCount);
    });

    this.renderSyncControl(containerEl, 'Backoff base (ms)', String(settings.syncControls.backoffBaseMs), async (value, committedValue) => {
      const backoffBaseMs = Number.parseInt(value.trim(), 10);
      if (!Number.isFinite(backoffBaseMs) || backoffBaseMs < 100) {
        new Notice('Backoff base must be at least 100 ms.');
        return committedValue;
      }

      await this.updateSyncControls({ backoffBaseMs });
      return String(backoffBaseMs);
    });

    this.renderSyncControl(
      containerEl,
      'Overlap window (seconds)',
      String(Math.floor(settings.syncControls.overlapWindowMs / 1_000)),
      async (value, committedValue) => {
        const seconds = Number.parseInt(value.trim(), 10);
        if (!Number.isFinite(seconds) || seconds < 0) {
          new Notice('Overlap window must be 0 seconds or greater.');
          return committedValue;
        }

        await this.updateSyncControls({ overlapWindowMs: seconds * 1_000 });
        return String(seconds);
      }
    );

    this.renderSyncControl(
      containerEl,
      'Bootstrap lookback (hours)',
      String(Math.floor(settings.syncControls.bootstrapLookbackMs / 3_600_000)),
      async (value, committedValue) => {
        const hours = Number.parseInt(value.trim(), 10);
        if (!Number.isFinite(hours) || hours < 1) {
          new Notice('Bootstrap lookback must be at least 1 hour.');
          return committedValue;
        }

        await this.updateSyncControls({ bootstrapLookbackMs: hours * 3_600_000 });
        return String(hours);
      }
    );
  }

  private renderSyncControl(
    containerEl: HTMLElement,
    name: string,
    value: string,
    persist: PersistTextValue
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
      persist: PersistTextValue;
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
      text.inputEl.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          text.inputEl.blur();
        }
      });
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

  private renderComputedProductFiltersSummary(containerEl: HTMLElement): void {
    const renderId = ++this.computedProductFiltersRenderId;
    const settings = this.plugin.getSettings();
    let summaryData: ComputedProductFiltersSummaryData = {
      activeFilterCount: 0,
      contributingSbomCount: 0,
      enabledSbomCount: settings.sboms.filter((sbom: ImportedSbomConfig) => sbom.enabled).length,
      filters: [],
      groups: [],
      manualFilterCount: this.normalizeProductFilters(settings.manualProductFilters).length
    };

    const card = containerEl.createDiv({ cls: 'vulndash-product-filters-card' });
    const header = card.createDiv({ cls: 'vulndash-product-filters-card-header' });
    header.createEl('h3', { cls: 'vulndash-product-filters-card-title', text: 'Computed Product Filters' });
    const countChip = header.createSpan({
      cls: 'vulndash-product-filters-chip vulndash-product-filters-chip-muted',
      text: 'Loading'
    });

    const descriptionEl = card.createEl('p', {
      cls: 'vulndash-product-filters-card-description',
      text: 'Loading derived product filters from the current SBOM workspace.'
    });

    const chipRow = card.createDiv({ cls: 'vulndash-product-filters-chip-row' });
    this.createProductFilterChip(chipRow, 'Loading filters', true);

    const actions = card.createDiv({ cls: 'vulndash-product-filters-summary-actions' });
    const viewButton = actions.createEl('button', { text: 'View Filters' });
    const copyButton = actions.createEl('button', { text: 'Copy All' });
    const recomputeButton = actions.createEl('button', { text: 'Recompute' });
    viewButton.disabled = true;
    copyButton.disabled = true;

    viewButton.addEventListener('click', () => {
      new ProductFiltersModal(this.app, {
        activeFilterCount: summaryData.activeFilterCount,
        contributingSbomCount: summaryData.contributingSbomCount,
        enabledSbomCount: summaryData.enabledSbomCount,
        filters: summaryData.filters,
        groups: summaryData.groups,
        manualFilterCount: summaryData.manualFilterCount,
        mode: this.plugin.getSettings().sbomImportMode
      }).open();
    });

    copyButton.addEventListener('click', () => {
      if (summaryData.filters.length === 0) {
        return;
      }

      void this.copyFiltersToClipboard(summaryData.filters, copyButton, 'Copy All');
    });

    recomputeButton.addEventListener('click', () => {
      void this.recomputeProductFilters(recomputeButton);
    });

    void (async () => {
      try {
        const nextSummaryData = await this.getComputedProductFiltersSummaryData();
        if (renderId !== this.computedProductFiltersRenderId) {
          return;
        }

        summaryData = nextSummaryData;
        countChip.textContent = `${summaryData.activeFilterCount} active`;
        descriptionEl.textContent = this.getComputedProductFiltersDescription(
          summaryData,
          this.plugin.getSettings().sbomImportMode
        );
        viewButton.disabled = false;
        copyButton.disabled = summaryData.filters.length === 0;

        chipRow.empty();
        if (summaryData.filters.length === 0) {
          this.createProductFilterChip(chipRow, 'No computed filters', true);
          return;
        }

        for (const filter of summaryData.filters.slice(0, PRODUCT_FILTER_PREVIEW_LIMIT)) {
          this.createProductFilterChip(chipRow, filter);
        }

        const hiddenCount = summaryData.filters.length - PRODUCT_FILTER_PREVIEW_LIMIT;
        if (hiddenCount > 0) {
          this.createProductFilterChip(chipRow, `+${hiddenCount} more`, true);
        }
      } catch {
        if (renderId !== this.computedProductFiltersRenderId) {
          return;
        }

        countChip.textContent = 'Unavailable';
        descriptionEl.textContent = 'Unable to load computed filters from the current SBOM workspace.';
        chipRow.empty();
        this.createProductFilterChip(chipRow, 'Unavailable', true);
      }
    })();
  }

  private async persistTextValue(text: TextComponent, save: () => Promise<void>): Promise<void> {
    text.inputEl.classList.add('vulndash-input-saving');
    text.inputEl.disabled = true;

    try {
      await save();
      text.inputEl.classList.add('vulndash-input-saved');
      window.setTimeout(() => {
        if (text.inputEl.isConnected) {
          text.inputEl.classList.remove('vulndash-input-saved');
        }
      }, SAVED_FEEDBACK_MS);
    } catch {
      new Notice('Unable to save setting.');
    } finally {
      text.inputEl.disabled = false;
      text.inputEl.classList.remove('vulndash-input-saving');
    }
  }

  private async getComputedProductFiltersSummaryData(): Promise<ComputedProductFiltersSummaryData> {
    const settings = this.plugin.getSettings();
    const enabledSboms = settings.sboms.filter((sbom: ImportedSbomConfig) => sbom.enabled);
    const manualFilters = this.normalizeProductFilters(settings.manualProductFilters);
    const resolvedComponentGroups = await Promise.all(enabledSboms.map(async (sbom: ImportedSbomConfig) => {
      const components = await this.plugin.getSbomComponents(sbom.id);
      const filters = this.normalizeProductFilters((components ?? [])
        .filter((component) => !component.excluded)
        .map((component) => component.displayName.trim())
        .filter((component) => component.length > 0));

      return {
        filters,
        label: sbom.label || 'Untitled SBOM',
        sbomId: sbom.id
      };
    }));

    const filters = this.normalizeProductFilters(resolvedComponentGroups.flatMap((group) => group.filters));
    const activeFilterCount = settings.sbomImportMode === 'append'
      ? this.normalizeProductFilters([...manualFilters, ...filters]).length
      : filters.length;

    return {
      activeFilterCount,
      contributingSbomCount: resolvedComponentGroups.filter((group) => group.filters.length > 0).length,
      enabledSbomCount: enabledSboms.length,
      filters,
      groups: resolvedComponentGroups
        .filter((group) => group.filters.length > 0)
        .sort((left, right) => left.label.localeCompare(right.label)),
      manualFilterCount: manualFilters.length
    };
  }

  private getComputedProductFiltersDescription(
    summaryData: ComputedProductFiltersSummaryData,
    mode: VulnDashSettings['sbomImportMode']
  ): string {
    if (summaryData.filters.length === 0) {
      if (summaryData.enabledSbomCount === 0) {
        return 'No computed filters are currently active. Enable an SBOM to derive filters automatically.';
      }

      return `No computed filters are currently active. Derived filters are computed from enabled SBOMs in ${mode} mode.`;
    }

    const sbomContext = summaryData.contributingSbomCount === summaryData.enabledSbomCount
      ? `${summaryData.enabledSbomCount} enabled SBOM${summaryData.enabledSbomCount === 1 ? '' : 's'}`
      : `${summaryData.contributingSbomCount} of ${summaryData.enabledSbomCount} enabled SBOMs`;

    if (mode === 'append' && summaryData.manualFilterCount > 0) {
      return `${summaryData.activeFilterCount} active filter${summaryData.activeFilterCount === 1 ? '' : 's'}: ${summaryData.filters.length} computed from ${sbomContext}, plus ${summaryData.manualFilterCount} manual filter${summaryData.manualFilterCount === 1 ? '' : 's'}.`;
    }

    return `${summaryData.activeFilterCount} active filter${summaryData.activeFilterCount === 1 ? '' : 's'} computed from ${sbomContext} in ${mode} mode.`;
  }

  private createProductFilterChip(containerEl: HTMLElement, label: string, muted = false): void {
    containerEl.createSpan({
      cls: `vulndash-product-filters-chip${muted ? ' vulndash-product-filters-chip-muted' : ''}`,
      text: label
    });
  }

  private async copyFiltersToClipboard(filters: string[], buttonEl: HTMLButtonElement, defaultLabel: string): Promise<void> {
    const buttonWasDisabled = buttonEl.disabled;
    buttonEl.disabled = true;

    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('Clipboard API unavailable');
      }

      await navigator.clipboard.writeText(filters.join('\n'));
      buttonEl.textContent = 'Copied';
      window.setTimeout(() => {
        if (!buttonEl.isConnected) {
          return;
        }

        buttonEl.textContent = defaultLabel;
        buttonEl.disabled = buttonWasDisabled;
      }, BUTTON_FEEDBACK_MS);
    } catch {
      buttonEl.textContent = defaultLabel;
      buttonEl.disabled = buttonWasDisabled;
      new Notice('Unable to copy computed filters.');
    }
  }

  private async recomputeProductFilters(buttonEl: HTMLButtonElement): Promise<void> {
    buttonEl.disabled = true;
    buttonEl.textContent = 'Recomputing...';

    try {
      await this.plugin.recomputeFilters();
      this.display();
    } catch {
      buttonEl.disabled = false;
      buttonEl.textContent = 'Recompute';
      new Notice('Unable to recompute computed filters.');
    }
  }

  private normalizeProductFilters(filters: string[]): string[] {
    return Array.from(new Set(filters
      .map((filter) => filter.trim())
      .filter((filter) => filter.length > 0)))
      .sort((left, right) => left.localeCompare(right));
  }

  private async refreshSbomSummary(setting: Setting): Promise<void> {
    try {
      const statuses = await this.plugin.getSbomFileStatuses();
      const summary = summarizeSbomWorkspace(this.plugin.getSettings().sboms, statuses);
      setting.setDesc(this.formatSbomSummaryText(summary));
    } catch {
      setting.setDesc('Unable to load SBOM workspace status. Runtime component data stays in memory, not plugin settings.');
    }
  }

  private formatSbomSummaryText(summary: ReturnType<typeof summarizeSbomWorkspace>): string {
    return [
      `${summary.configured} configured`,
      `${summary.enabled} enabled`,
      `${summary.withErrors} with errors`,
      `${summary.changed} changed since last sync`,
      'Runtime component data stays in memory, not plugin settings.'
    ].join(' • ');
  }

  private async updateBuiltInFeed(
    feedId: string,
    feedType: VulnDashSettings['feeds'][number]['type'],
    patch: Partial<VulnDashSettings['feeds'][number]>,
    rootPatch: Partial<VulnDashSettings> = {}
  ): Promise<void> {
    const current = this.plugin.getSettings();
    const feedExists = current.feeds.some((f) => f.id === feedId && f.type === feedType);

    // Safely append the built-in feed if it was missing from the configuration array
    const nextFeeds = feedExists
      ? current.feeds.map((feed) => (
          feed.id === feedId && feed.type === feedType
            ? { ...feed, ...patch } as VulnDashSettings['feeds'][number]
            : feed
        ))
      : [...current.feeds, { id: feedId, type: feedType, enabled: false, ...patch } as VulnDashSettings['feeds'][number]];

    await this.plugin.updateSettings({
      ...current,
      ...rootPatch,
      feeds: nextFeeds
    });
  }

  private async updateSyncControls(patch: Partial<VulnDashSettings['syncControls']>): Promise<void> {
    const current = this.plugin.getSettings();
    await this.plugin.updateSettings({
      ...current,
      syncControls: {
        ...current.syncControls,
        ...patch
      }
    });
  }
}
