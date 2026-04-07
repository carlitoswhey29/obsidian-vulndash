import {
  App,
  Notice,
  normalizePath,
  Plugin,
  PluginSettingTab,
  Setting,
  WorkspaceLeaf
} from 'obsidian';
import { AlertEngine } from './application/services/AlertEngine';
import { PollingOrchestrator } from './application/services/PollingOrchestrator';
import type { ColumnVisibility, VulnDashSettings } from './application/services/types';
import type { Vulnerability } from './domain/entities/Vulnerability';
import { GitHubAdvisoryClient } from './infrastructure/api/GitHubAdvisoryClient';
import { HttpClient } from './infrastructure/api/HttpClient';
import { NvdClient } from './infrastructure/api/NvdClient';
import { VULNDASH_VIEW_TYPE, VulnDashView } from './infrastructure/obsidian/VulnDashView';

const DEFAULT_COLUMN_VISIBILITY: ColumnVisibility = {
  id: true,
  title: true,
  source: true,
  severity: true,
  cvssScore: true,
  publishedAt: true
};

const DEFAULT_SETTINGS: VulnDashSettings = {
  pollingIntervalMs: 60_000,
  keywordFilters: [],
  productFilters: [],
  minSeverity: 'MEDIUM',
  minCvssScore: 4.0,
  nvdApiKey: '',
  githubToken: '',
  systemNotificationsEnabled: true,
  desktopAlertsHighOrCritical: false,
  cacheDurationMs: 60_000,
  maxResults: 200,
  defaultSortOrder: 'publishedAt',
  colorCodedSeverity: true,
  columnVisibility: DEFAULT_COLUMN_VISIBILITY,
  keywordRegexEnabled: false,
  enableNvdFeed: true,
  enableGithubFeed: true,
  autoNoteCreationEnabled: false,
  autoNoteFolder: 'VulnDash Alerts',
  sbomPath: ''
};

interface SbomComponent {
  name?: unknown;
}

interface SbomDocument {
  components?: SbomComponent[];
}

export default class VulnDashPlugin extends Plugin {
  private settings: VulnDashSettings = DEFAULT_SETTINGS;
  private stopPolling: (() => void) | null = null;
  private readonly alertEngine = new AlertEngine();
  private lastFetchAt = 0;
  private cachedVulnerabilities: Vulnerability[] = [];
  private previousVisibleIds = new Set<string>();

  public override async onload(): Promise<void> {
    await this.loadSettings();

    this.registerView(VULNDASH_VIEW_TYPE, (leaf) =>
      new VulnDashView(leaf, async () => {
        await this.refreshNow();
      })
    );

    this.addRibbonIcon('shield-alert', 'Open VulnDash', () => {
      void this.activateView();
    });

    this.addCommand({
      id: 'vulndash-open',
      name: 'Open vulnerability dashboard',
      callback: () => {
        void this.activateView();
      }
    });

    this.addSettingTab(new VulnDashSettingTab(this.app, this));

    this.startPolling();
    await this.activateView();
  }

  public override onunload(): void {
    if (this.stopPolling) {
      this.stopPolling();
      this.stopPolling = null;
    }
  }

  public async refreshNow(): Promise<void> {
    const now = Date.now();
    const cacheValid = now - this.lastFetchAt <= this.settings.cacheDurationMs;
    if (cacheValid && this.cachedVulnerabilities.length > 0) {
      await this.processData(this.cachedVulnerabilities);
      return;
    }

    const orchestrator = this.createOrchestrator();
    try {
      const all = await orchestrator.pollOnce();
      this.cachedVulnerabilities = all;
      this.lastFetchAt = Date.now();
      await this.processData(all);
    } catch {
      new Notice('VulnDash refresh failed. Check your network or API tokens.');
    }
  }

  public async updateSettings(next: VulnDashSettings): Promise<void> {
    this.settings = next;
    await this.saveSettings();
    this.restartPolling();
    this.updateViewSettings();
    await this.refreshNow();
  }

  public getSettings(): VulnDashSettings {
    return this.settings;
  }

  public async importProductFiltersFromSbom(): Promise<void> {
    const path = this.settings.sbomPath.trim();
    if (!path) {
      new Notice('Set an SBOM path before importing products.');
      return;
    }

    try {
      const raw = await this.app.vault.adapter.read(normalizePath(path));
      const parsed = JSON.parse(raw) as SbomDocument;
      const components = parsed.components ?? [];
      const productFilters = Array.from(new Set(components
        .map((component) => component.name)
        .filter((name): name is string => typeof name === 'string' && name.trim().length > 0)
        .map((name) => name.trim())));

      await this.updateSettings({ ...this.settings, productFilters });
      new Notice(`Imported ${productFilters.length} products from SBOM.`);
    } catch {
      new Notice('Unable to read or parse SBOM path.');
    }
  }

  private async processData(vulnerabilities: Vulnerability[]): Promise<void> {
    const filtered = this.alertEngine.filter(vulnerabilities, this.settings);
    this.updateView(filtered);
    await this.notifyOnNewItems(filtered);
  }

  private async notifyOnNewItems(vulnerabilities: Vulnerability[]): Promise<void> {
    const current = new Set(vulnerabilities.map((vulnerability) => vulnerability.id));
    const newItems = vulnerabilities.filter((vulnerability) => !this.previousVisibleIds.has(vulnerability.id));
    this.previousVisibleIds = current;

    if (newItems.length === 0) {
      return;
    }

    if (this.settings.systemNotificationsEnabled) {
      new Notice(`VulnDash detected ${newItems.length} new matching vulnerabilities.`);
    }

    const highPriority = newItems.filter((vulnerability) =>
      vulnerability.severity === 'CRITICAL' || vulnerability.severity === 'HIGH'
    );

    if (this.settings.desktopAlertsHighOrCritical) {
      this.sendDesktopAlert(highPriority);
    }

    if (this.settings.autoNoteCreationEnabled) {
      await this.createCriticalNotes(newItems.filter((vulnerability) => vulnerability.severity === 'CRITICAL'));
    }
  }

  private sendDesktopAlert(vulnerabilities: Vulnerability[]): void {
    if (vulnerabilities.length === 0) {
      return;
    }

    if (!('Notification' in window)) {
      return;
    }

    if (Notification.permission === 'granted') {
      const top = vulnerabilities[0];
      if (!top) {
        return;
      }
      new Notification('VulnDash high-severity alert', {
        body: `${vulnerabilities.length} HIGH/CRITICAL issue(s). Latest: ${top.id}`
      });
      return;
    }

    if (Notification.permission === 'default') {
      void Notification.requestPermission();
    }
  }

  private async createCriticalNotes(vulnerabilities: Vulnerability[]): Promise<void> {
    if (vulnerabilities.length === 0) {
      return;
    }

    await this.ensureFolder(this.settings.autoNoteFolder);

    for (const vulnerability of vulnerabilities) {
      const safeId = vulnerability.id.replace(/[^A-Za-z0-9._-]/g, '-');
      const notePath = normalizePath(`${this.settings.autoNoteFolder}/${safeId}.md`);
      const exists = await this.app.vault.adapter.exists(notePath);
      if (exists) {
        continue;
      }

      const body = [
        `# ${vulnerability.id} (${vulnerability.severity})`,
        '',
        `- Source: ${vulnerability.source}`,
        `- CVSS: ${vulnerability.cvssScore.toFixed(1)}`,
        `- Published: ${vulnerability.publishedAt}`,
        '',
        vulnerability.summary,
        '',
        '## References',
        ...vulnerability.references.map((reference) => `- ${reference}`)
      ].join('\n');

      await this.app.vault.create(notePath, body);
    }
  }

  private async ensureFolder(folderPath: string): Promise<void> {
    const cleanPath = normalizePath(folderPath);
    if (!cleanPath || cleanPath === '/') {
      return;
    }

    if (await this.app.vault.adapter.exists(cleanPath)) {
      return;
    }

    const parts = cleanPath.split('/').filter(Boolean);
    let current = '';
    for (const part of parts) {
      current = current ? `${current}/${part}` : part;
      const exists = await this.app.vault.adapter.exists(current);
      if (!exists) {
        await this.app.vault.createFolder(current);
      }
    }
  }

  private startPolling(): void {
    const orchestrator = this.createOrchestrator();
    this.stopPolling = orchestrator.start(this.settings.pollingIntervalMs, (vulns) => {
      this.cachedVulnerabilities = vulns;
      this.lastFetchAt = Date.now();
      void this.processData(vulns);
    });
  }

  private restartPolling(): void {
    if (this.stopPolling) {
      this.stopPolling();
      this.stopPolling = null;
    }
    this.startPolling();
  }

  private createOrchestrator(): PollingOrchestrator {
    const client = new HttpClient();
    const feeds = [];

    if (this.settings.enableNvdFeed) {
      feeds.push(new NvdClient(client, this.settings.nvdApiKey));
    }

    if (this.settings.enableGithubFeed) {
      feeds.push(new GitHubAdvisoryClient(client, this.settings.githubToken));
    }

    return new PollingOrchestrator(feeds);
  }

  private updateView(vulnerabilities: Vulnerability[]): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setData(vulnerabilities);
      }
    }
  }

  private updateViewSettings(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setSettings(this.settings);
      }
    }
  }

  private async activateView(): Promise<void> {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    let leaf: WorkspaceLeaf | null = leaves[0] ?? null;

    if (!leaf) {
      const rightLeaf = this.app.workspace.getRightLeaf(false);
      if (!rightLeaf) {
        new Notice('Unable to open VulnDash view.');
        return;
      }
      leaf = rightLeaf;
      await leaf.setViewState({
        type: VULNDASH_VIEW_TYPE,
        active: true
      });
    }

    this.app.workspace.revealLeaf(leaf);
    this.updateViewSettings();
    await this.refreshNow();
  }

  private async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    this.settings = {
      ...DEFAULT_SETTINGS,
      ...(loaded as Partial<VulnDashSettings> | null),
      columnVisibility: {
        ...DEFAULT_COLUMN_VISIBILITY,
        ...((loaded as Partial<VulnDashSettings> | null)?.columnVisibility ?? {})
      }
    };
  }

  private async saveSettings(): Promise<void> {
    await this.saveData(this.settings);
  }
}

class VulnDashSettingTab extends PluginSettingTab {
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
      .addText((text) =>
        text
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
      .addText((text) =>
        text.setValue(settings.keywordFilters.join(',')).onChange(async (value) => {
          await this.plugin.updateSettings({
            ...this.plugin.getSettings(),
            keywordFilters: value.split(',').map((v) => v.trim()).filter(Boolean)
          });
        })
      );

    new Setting(containerEl)
      .setName('Treat keywords as regular expressions')
      .setDesc('Enables advanced keyword matching with case-insensitive regex patterns.')
      .addToggle((toggle) =>
        toggle.setValue(settings.keywordRegexEnabled).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), keywordRegexEnabled: value });
        })
      );

    new Setting(containerEl)
      .setName('Product filters (comma-separated)')
      .addText((text) =>
        text.setValue(settings.productFilters.join(',')).onChange(async (value) => {
          await this.plugin.updateSettings({
            ...this.plugin.getSettings(),
            productFilters: value.split(',').map((v) => v.trim()).filter(Boolean)
          });
        })
      );

    new Setting(containerEl)
      .setName('Minimum CVSS score')
      .addText((text) =>
        text.setValue(String(settings.minCvssScore)).onChange(async (value) => {
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
      .addToggle((toggle) =>
        toggle.setValue(settings.systemNotificationsEnabled).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), systemNotificationsEnabled: value });
        })
      );

    new Setting(containerEl)
      .setName('Desktop alerts for HIGH/CRITICAL')
      .setDesc('Use OS-level notifications for urgent vulnerabilities.')
      .addToggle((toggle) =>
        toggle.setValue(settings.desktopAlertsHighOrCritical).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), desktopAlertsHighOrCritical: value });
        })
      );

    containerEl.createEl('h3', { text: 'Data Persistence & Performance' });

    new Setting(containerEl)
      .setName('Cache duration (seconds)')
      .setDesc('How long fetched vulnerability data remains in memory before refresh.')
      .addText((text) =>
        text.setValue(String(Math.floor(settings.cacheDurationMs / 1000))).onChange(async (value) => {
          const seconds = Number.parseInt(value, 10);
          if (Number.isNaN(seconds) || seconds < 0) return;
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), cacheDurationMs: seconds * 1000 });
        })
      );

    new Setting(containerEl)
      .setName('Maximum results shown')
      .setDesc('Limits how many vulnerabilities are rendered in the dashboard.')
      .addText((text) =>
        text.setValue(String(settings.maxResults)).onChange(async (value) => {
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
      .addToggle((toggle) =>
        toggle.setValue(settings.colorCodedSeverity).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), colorCodedSeverity: value });
        })
      );

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
        .addToggle((toggle) =>
          toggle.setValue(settings.columnVisibility[columnDef.key]).onChange(async (value) => {
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
      .addToggle((toggle) =>
        toggle.setValue(settings.enableNvdFeed).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), enableNvdFeed: value });
        })
      );

    new Setting(containerEl)
      .setName('Enable GitHub advisories feed')
      .addToggle((toggle) =>
        toggle.setValue(settings.enableGithubFeed).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), enableGithubFeed: value });
        })
      );

    containerEl.createEl('h3', { text: 'Integration & Export' });

    new Setting(containerEl)
      .setName('Auto-note creation for CRITICAL')
      .addToggle((toggle) =>
        toggle.setValue(settings.autoNoteCreationEnabled).onChange(async (value) => {
          await this.plugin.updateSettings({ ...this.plugin.getSettings(), autoNoteCreationEnabled: value });
        })
      );

    new Setting(containerEl)
      .setName('Auto-note folder')
      .addText((text) =>
        text.setValue(settings.autoNoteFolder).onChange(async (value) => {
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
      .addText((text) =>
        text.setPlaceholder('reports/sbom.json').setValue(settings.sbomPath).onChange(async (value) => {
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
