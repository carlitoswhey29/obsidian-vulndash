import {
  Notice,
  normalizePath,
  Plugin,
  WorkspaceLeaf
} from 'obsidian';
import { AlertEngine } from './application/services/AlertEngine';
import { buildFeedsFromConfig } from './application/services/FeedFactory';
import { PollingOrchestrator } from './application/services/PollingOrchestrator';
import { buildFailureNoticeMessage, buildVisibilityDiagnostics, summarizeSyncResults } from './application/services/SyncOutcomeDiagnostics';
import type { ColumnVisibility, FeedConfig, VulnDashSettings } from './application/services/types';
import type { Vulnerability } from './domain/entities/Vulnerability';
import { HttpClient } from './infrastructure/api/HttpClient';
import { buildVulnerabilityNoteBody } from './infrastructure/obsidian/VulnerabilityNote';
import { VULNDASH_VIEW_TYPE, VulnDashView } from './infrastructure/obsidian/VulnDashView';
import { VulnDashSettingTab } from './infrastructure/obsidian/VulnDashSettingsTab';
import { decryptSecret, ENCRYPTED_SECRET_PREFIX, encryptSecret } from './infrastructure/utils/crypto';
import { logger } from './infrastructure/utils/logger';

const DEFAULT_COLUMN_VISIBILITY: ColumnVisibility = {
  id: true,
  title: true,
  source: true,
  severity: true,
  cvssScore: true,
  publishedAt: true
};

const DEFAULT_FEEDS: FeedConfig[] = [
  { id: 'nvd-default', name: 'NVD', type: 'nvd', enabled: true },
  { id: 'github-advisories-default', name: 'GitHub', type: 'github_advisory', enabled: true }
];

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
  sbomPath: '',
  syncControls: {
    maxPages: 10,
    maxItems: 500,
    retryCount: 3,
    backoffBaseMs: 1_000,
    overlapWindowMs: 180_000,
    bootstrapLookbackMs: 86_400_000,
    debugHttpMetadata: false
  },
  sourceSyncCursor: {},
  settingsVersion: 2,
  feeds: DEFAULT_FEEDS.map((feed) => ({ ...feed }))
};

interface SbomComponent {
  name?: unknown;
}

interface SbomDocument {
  components?: SbomComponent[];
}

interface FeedAuthHealth {
  status: 'unknown' | 'valid' | 'auth_failed' | 'error';
  checkedAt?: string;
  message?: string;
}

const cloneFeedConfig = (feed: FeedConfig): FeedConfig => ({ ...feed });

const migrateLegacySettings = (settings: Partial<VulnDashSettings>): VulnDashSettings => {
  const hasDynamicFeeds = Array.isArray(settings.feeds) && settings.feeds.length > 0;
  const feeds = hasDynamicFeeds
    ? (settings.feeds ?? []).map((feed) => cloneFeedConfig(feed))
    : DEFAULT_FEEDS.map((feed) => cloneFeedConfig(feed));

  if (!hasDynamicFeeds) {
    const nvdFeed = feeds.find((feed): feed is Extract<FeedConfig, { type: 'nvd' }> => feed.type === 'nvd' && feed.id === 'nvd-default');
    if (nvdFeed && settings.nvdApiKey) {
      nvdFeed.apiKey = settings.nvdApiKey;
    }
    if (typeof settings.enableNvdFeed === 'boolean' && nvdFeed) {
      nvdFeed.enabled = settings.enableNvdFeed;
    }

    const githubFeed = feeds.find((feed) => feed.type === 'github_advisory' && feed.id === 'github-advisories-default');
    if (githubFeed && settings.githubToken) {
      githubFeed.token = settings.githubToken;
    }
    if (typeof settings.enableGithubFeed === 'boolean' && githubFeed) {
      githubFeed.enabled = settings.enableGithubFeed;
    }
  }

  const cursor = { ...(settings.sourceSyncCursor ?? {}) };
  const legacyNvdCursor = cursor.NVD;
  const legacyGithubCursor = cursor.GitHub;
  if (legacyNvdCursor && !cursor['nvd-default']) {
    cursor['nvd-default'] = legacyNvdCursor;
  }
  if (legacyGithubCursor && !cursor['github-advisories-default']) {
    cursor['github-advisories-default'] = legacyGithubCursor;
  }
  delete cursor.NVD;
  delete cursor.GitHub;

  return {
    ...DEFAULT_SETTINGS,
    ...settings,
    settingsVersion: 2,
    feeds,
    sourceSyncCursor: cursor,
    columnVisibility: {
      ...DEFAULT_COLUMN_VISIBILITY,
      ...(settings.columnVisibility ?? {})
    },
    syncControls: {
      ...DEFAULT_SETTINGS.syncControls,
      ...(settings.syncControls ?? {})
    }
  };
};

export default class VulnDashPlugin extends Plugin {
  private settings: VulnDashSettings = DEFAULT_SETTINGS;
  private stopPolling: (() => void) | null = null;
  private pollingEnabled = false;
  private readonly alertEngine = new AlertEngine();
  private lastFetchAt = 0;
  private cachedVulnerabilities: Vulnerability[] = [];
  private previousVisibleIds = new Set<string>();
  private authHealthByFeedId: Record<string, FeedAuthHealth> = {};

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

    this.addCommand({
      id: 'vulndash-validate-feed-connections',
      name: 'Validate feed connections',
      callback: () => {
        void this.validateFeedConnections();
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
      const outcome = await orchestrator.pollOnce();
      const syncSummaries = summarizeSyncResults(outcome.results);
      for (const summary of syncSummaries) {
        logger.info('[vulndash.sync.feed_summary]', summary);
      }
      this.updateAuthHealth(outcome.results);
      const failureNotice = buildFailureNoticeMessage(outcome.results);
      if (failureNotice) {
        new Notice(failureNotice);
      }
      this.cachedVulnerabilities = outcome.vulnerabilities;
      this.settings.sourceSyncCursor = outcome.sourceSyncCursor;
      await this.saveSettings();
      this.lastFetchAt = Date.now();
      await this.processData(outcome.vulnerabilities);
    } catch (error: unknown) {
      logger.warn('[vulndash.refresh.failure]', error instanceof Error ? { name: error.name, message: error.message } : { message: 'Unknown refresh error' });
      new Notice('VulnDash refresh failed. Check your network or API tokens.');
    }
  }

  public async updateSettings(next: VulnDashSettings): Promise<void> {
    this.settings = await this.encryptSettingsSecrets(next);
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
    const diagnostics = buildVisibilityDiagnostics(vulnerabilities, filtered);
    logger.info('[vulndash.filter.visibility]', diagnostics);
    this.updateView(filtered);
    await this.notifyOnNewItems(filtered);
  }

  private async validateFeedConnections(): Promise<void> {
    const client = new HttpClient();
    const feeds = buildFeedsFromConfig(
      this.settings.feeds,
      client,
      this.settings.syncControls,
      async (secret) => this.resolveSecret(secret)
    );
    const failures: string[] = [];

    for (const feed of feeds) {
      const checkedAt = new Date().toISOString();
      if (!feed.validateConnection) {
        this.authHealthByFeedId[feed.id] = {
          status: 'unknown',
          checkedAt,
          message: `${feed.name} does not support connection validation.`
        };
        continue;
      }

      const result = await feed.validateConnection(new AbortController().signal);
      this.authHealthByFeedId[feed.id] = {
        status: result.ok ? 'valid' : 'error',
        checkedAt,
        message: result.message
      };

      logger.info('[vulndash.feed.validation]', {
        source: feed.name,
        feedId: feed.id,
        ok: result.ok,
        message: result.message
      });

      if (!result.ok) {
        failures.push(feed.name);
      }
    }

    if (failures.length > 0) {
      new Notice(`VulnDash feed validation failed for: ${failures.join(', ')}. Token or API key may be expired, revoked, invalid, or missing required permissions.`);
      return;
    }

    new Notice('VulnDash feed connections validated.');
  }

  private updateAuthHealth(results: Array<{
    feedId: string;
    success: boolean;
    authFailure?: { reason: 'unauthorized' | 'forbidden' };
  }>): void {
    const checkedAt = new Date().toISOString();
    for (const result of results) {
      this.authHealthByFeedId[result.feedId] = result.authFailure
        ? {
          status: 'auth_failed',
          checkedAt,
          message: result.authFailure.reason === 'unauthorized'
            ? 'Authentication failed. Token or API key may be expired, revoked, or invalid.'
            : 'Authorization failed. Token or API key may be missing required permissions.'
        }
        : {
          status: result.success ? 'valid' : 'error',
          checkedAt,
          ...(result.success ? {} : { message: 'Last sync failed.' })
        };
    }
  }

  private async notifyOnNewItems(vulnerabilities: Vulnerability[]): Promise<void> {
    const current = new Set(vulnerabilities.map((vulnerability) => `${vulnerability.source}:${vulnerability.id}`));
    const newItems = vulnerabilities.filter((vulnerability) => !this.previousVisibleIds.has(`${vulnerability.source}:${vulnerability.id}`));
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

      await this.app.vault.create(notePath, buildVulnerabilityNoteBody(vulnerability));
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
    this.stopPolling = orchestrator.start(this.settings.pollingIntervalMs, (outcome) => {
      this.cachedVulnerabilities = outcome.vulnerabilities;
      this.settings.sourceSyncCursor = outcome.sourceSyncCursor;
      void this.saveSettings();
      this.lastFetchAt = Date.now();
      void this.processData(outcome.vulnerabilities);
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
    const feeds = buildFeedsFromConfig(
      this.settings.feeds,
      client,
      this.settings.syncControls,
      async (secret) => this.resolveSecret(secret)
    );

    return new PollingOrchestrator(feeds, this.settings.syncControls, {
      cache: this.cachedVulnerabilities,
      sourceSyncCursor: this.settings.sourceSyncCursor
    });
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
    const loadedSettings = (loaded as Partial<VulnDashSettings> | null) ?? null;

    const migrated = migrateLegacySettings({
      ...(loadedSettings ?? {})
    });
    this.settings = await this.encryptSettingsSecrets(migrated);

    if (this.hasPlaintextSecrets(migrated) || (loadedSettings?.settingsVersion ?? 0) < 2) {
      await this.saveSettings();
    }
  }

  private async saveSettings(): Promise<void> {
    const dataToSave = await this.encryptSettingsSecrets(this.settings);
    this.settings = dataToSave;
    await this.saveData(dataToSave);
  }

  private async encryptSettingsSecrets(settings: VulnDashSettings): Promise<VulnDashSettings> {
    const encryptedNvd = await this.serializeSecret(settings.nvdApiKey);
    const encryptedGithub = await this.serializeSecret(settings.githubToken);
    const feeds = await Promise.all(settings.feeds.map(async (feed) => {
      if (feed.type === 'nvd') {
        return {
          ...feed,
          apiKey: await this.serializeSecret(feed.apiKey ?? ''),
          ...(feed.token ? { token: await this.serializeSecret(feed.token) } : {})
        };
      }
      if (feed.token) {
        return {
          ...feed,
          token: await this.serializeSecret(feed.token)
        };
      }
      return { ...feed };
    }));

    return {
       ...settings,
       nvdApiKey: encryptedNvd,
       githubToken: encryptedGithub,
       feeds
    };
  }

  private async serializeSecret(secret: string): Promise<string> {
    if (!secret) {
      return '';
    }
    if (secret.startsWith(ENCRYPTED_SECRET_PREFIX)) {
      return secret;
    }
    const encrypted = await encryptSecret(secret);
    if (!encrypted) {
      return '';
    }
    return `${ENCRYPTED_SECRET_PREFIX}${encrypted}`;
  }

  private async loadSecret(secret: string): Promise<{ value: string; needsMigration: boolean; decryptionFailed: boolean }> {
    if (!secret) {
      return { value: '', needsMigration: false, decryptionFailed: false };
    }

    if (!secret.startsWith(ENCRYPTED_SECRET_PREFIX)) {
      return { value: secret, needsMigration: true, decryptionFailed: false };
    }

    const encryptedPayload = secret.slice(ENCRYPTED_SECRET_PREFIX.length);
    const decrypted = await decryptSecret(encryptedPayload);
    if (decrypted.status === 'success') {
      return { value: decrypted.value, needsMigration: false, decryptionFailed: false };
    }

    return { value: '', needsMigration: false, decryptionFailed: true };
  }

  private async resolveSecret(secret: string): Promise<string> {
    if (!secret || !secret.startsWith(ENCRYPTED_SECRET_PREFIX)) {
      return secret;
    }

    const decrypted = await this.loadSecret(secret);
    if (decrypted.decryptionFailed) {
      new Notice('VulnDash could not decrypt a stored API key or token. Please re-enter it.');
    }

    // JavaScript strings cannot be reliably zeroized in Electron/V8. Keep this value scoped to
    // the immediate request path and never pass it to logs, notices, or long-lived feed fields.
    return decrypted.value;
  }

  private hasPlaintextSecrets(settings: VulnDashSettings): boolean {
    const hasPlaintext = (secret: string | undefined): boolean =>
      Boolean(secret && !secret.startsWith(ENCRYPTED_SECRET_PREFIX));

    return hasPlaintext(settings.nvdApiKey)
      || hasPlaintext(settings.githubToken)
      || settings.feeds.some((feed) => hasPlaintext(feed.token) || (feed.type === 'nvd' && hasPlaintext(feed.apiKey)));
  }
}
