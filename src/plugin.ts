import {
  Notice,
  normalizePath,
  Plugin,
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
import { VulnDashSettingTab } from './VulnDashSettingTab';

const DEFAULT_COLUMN_VISIBILITY: ColumnVisibility = {
  id: true,
  title: true,
  source: true,
  severity: true,
  cvssScore: true,
  publishedAt: true
};

export const DEFAULT_SETTINGS: VulnDashSettings = {
  pollingIntervalMs: 60_000,
  pollOnStartup: true,
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
  private pollingEnabled = false;
  private readonly alertEngine = new AlertEngine();
  private lastFetchAt = 0;
  private cachedVulnerabilities: Vulnerability[] = [];
  private previousVisibleIds = new Set<string>();

  public override async onload(): Promise<void> {
    await this.loadSettings();

    this.registerView(VULNDASH_VIEW_TYPE, (leaf) =>
      new VulnDashView(
        leaf,
        async () => {
          await this.refreshNow();
        },
        async () => this.togglePolling(),
        () => this.pollingEnabled
      )
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

    if (this.settings.pollOnStartup) {
      this.startPolling();
    }
    await this.activateView();
  }

  public override onunload(): void {
    this.stopPollingLoop();
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
    this.updateViewPollingState();
    await this.refreshNow();
  }

  public getSettings(): VulnDashSettings {
    return this.settings;
  }

  public async togglePolling(): Promise<void> {
    if (this.pollingEnabled) {
      this.stopPollingLoop();
      this.updateViewPollingState();
      return;
    }

    this.startPolling();
    this.updateViewPollingState();
    await this.refreshNow();
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

  /** Creates individual notes for critical vulnerabilities if auto-note creation is enabled.
   * Notes are only created for vulnerabilities that are newly detected as critical to avoid duplicates.
   */
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
    if (this.pollingEnabled) {
      return;
    }

    const orchestrator = this.createOrchestrator();
    this.pollingEnabled = true;
    this.stopPolling = orchestrator.start(this.settings.pollingIntervalMs, (vulns) => {
      this.cachedVulnerabilities = vulns;
      this.lastFetchAt = Date.now();
      void this.processData(vulns);
    });
  }

  private restartPolling(): void {
    const wasPolling = this.pollingEnabled;
    this.stopPollingLoop();
    if (wasPolling || this.settings.pollOnStartup) {
      this.startPolling();
    }
  }

  private stopPollingLoop(): void {
    if (this.stopPolling) {
      this.stopPolling();
      this.stopPolling = null;
    }
    this.pollingEnabled = false;
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

  private updateViewPollingState(): void {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view;
      if (view instanceof VulnDashView) {
        view.setPollingEnabled(this.pollingEnabled);
      }
    }
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
    this.updateViewPollingState();
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
