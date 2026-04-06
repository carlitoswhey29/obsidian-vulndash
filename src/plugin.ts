import {
  App,
  Notice,
  Plugin,
  PluginSettingTab,
  Setting,
  WorkspaceLeaf
} from 'obsidian';
import { AlertEngine } from './application/services/AlertEngine';
import { PollingOrchestrator } from './application/services/PollingOrchestrator';
import type { VulnDashSettings } from './application/services/types';
import type { Vulnerability } from './domain/entities/Vulnerability';
import { GitHubAdvisoryClient } from './infrastructure/api/GitHubAdvisoryClient';
import { HttpClient } from './infrastructure/api/HttpClient';
import { NvdClient } from './infrastructure/api/NvdClient';
import { VULNDASH_VIEW_TYPE, VulnDashView } from './infrastructure/obsidian/VulnDashView';

const DEFAULT_SETTINGS: VulnDashSettings = {
  pollingIntervalMs: 60_000,
  keywordFilters: [],
  productFilters: [],
  minSeverity: 'MEDIUM',
  minCvssScore: 4.0,
  nvdApiKey: '',
  githubToken: ''
};

export default class VulnDashPlugin extends Plugin {
  private settings: VulnDashSettings = DEFAULT_SETTINGS;
  private stopPolling: (() => void) | null = null;
  private readonly alertEngine = new AlertEngine();

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
    const orchestrator = this.createOrchestrator();
    try {
      const all = await orchestrator.pollOnce();
      const filtered = this.alertEngine.filter(all, this.settings);
      this.updateView(filtered);
    } catch {
      new Notice('VulnDash refresh failed. Check your network or API tokens.');
    }
  }

  public async updateSettings(next: VulnDashSettings): Promise<void> {
    this.settings = next;
    await this.saveSettings();
    this.restartPolling();
    await this.refreshNow();
  }

  public getSettings(): VulnDashSettings {
    return this.settings;
  }

  private startPolling(): void {
    const orchestrator = this.createOrchestrator();
    this.stopPolling = orchestrator.start(this.settings.pollingIntervalMs, (vulns) => {
      const filtered = this.alertEngine.filter(vulns, this.settings);
      this.updateView(filtered);
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
    return new PollingOrchestrator([
      new NvdClient(client, this.settings.nvdApiKey),
      new GitHubAdvisoryClient(client, this.settings.githubToken)
    ]);
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

  private async activateView(): Promise<void> {
    const leaves = this.app.workspace.getLeavesOfType(VULNDASH_VIEW_TYPE);
    let leaf: WorkspaceLeaf | null = leaves[0] ?? null;

    if (!leaf) {
      const rightLeaf = this.app.workspace.getRightLeaf(false);
      if (!rightLeaf) {
        new Notice("Unable to open VulnDash view.");
        return;
      }
      leaf = rightLeaf;
      await leaf.setViewState({
        type: VULNDASH_VIEW_TYPE,
        active: true
      });
    }

    this.app.workspace.revealLeaf(leaf);
    await this.refreshNow();
  }

  private async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    this.settings = { ...DEFAULT_SETTINGS, ...(loaded as Partial<VulnDashSettings> | null) };
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
