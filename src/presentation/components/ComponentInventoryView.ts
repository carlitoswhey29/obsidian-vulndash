import type { ComponentInventorySnapshot, ComponentInventoryWorkspaceSnapshot } from '../../application/sbom/types';
import { ComponentFilterBar } from './ComponentFilterBar';
import {
  type ComponentInventoryDisplayEntry,
  createDefaultComponentInventoryFilters,
  deriveComponentInventoryState
} from './ComponentInventoryStore';
import { renderComponentRow, type ComponentRowRendererCallbacks } from './ComponentRowRenderer';
import type { ComponentDetailsRenderer } from './ComponentDetailPanel';

export interface ComponentInventoryViewCallbacks {
  detailsRenderer: ComponentDetailsRenderer;
  loadSnapshot: () => Promise<ComponentInventoryWorkspaceSnapshot>;
  onDisableComponent: (componentKey: string) => Promise<void>;
  onEnableComponent: (componentKey: string) => Promise<void>;
  onFollowComponent: (componentKey: string) => Promise<void>;
  onOpenNote?: (notePath: string) => void;
  onUnfollowComponent: (componentKey: string) => Promise<void>;
}

type InventoryLoadState =
  | { status: 'idle' | 'loading' }
  | { snapshot: ComponentInventoryWorkspaceSnapshot; status: 'ready' }
  | { message: string; status: 'error' };

export class ComponentInventoryView {
  private readonly expandedKeys = new Set<string>();
  private readonly filterBar = new ComponentFilterBar({
    onChange: (filters) => {
      this.filters = filters;
      this.renderResults();
    },
    onReset: () => {
      this.filters = createDefaultComponentInventoryFilters();
      this.renderFilterBar();
      this.renderResults();
    }
  });
  private filters = createDefaultComponentInventoryFilters();
  private filterHostEl: HTMLDivElement | null = null;
  private isActive = false;
  private isDirty = true;
  private loadState: InventoryLoadState = { status: 'idle' };
  private renderToken = 0;
  private resultsHostEl: HTMLDivElement | null = null;
  private rootEl: HTMLDivElement | null = null;
  private summaryHostEl: HTMLDivElement | null = null;

  public constructor(
    private readonly callbacks: ComponentInventoryViewCallbacks
  ) {}

  public mount(containerEl: HTMLElement): void {
    if (this.rootEl) {
      return;
    }

    this.rootEl = containerEl.createDiv({ cls: 'vulndash-component-inventory-view' });
    this.summaryHostEl = this.rootEl.createDiv();
    this.filterHostEl = this.rootEl.createDiv({ cls: 'vulndash-component-inventory-filter-shell' });
    this.resultsHostEl = this.rootEl.createDiv();
  }

  public async setActive(active: boolean): Promise<void> {
    this.isActive = active;

    if (this.rootEl) {
      this.rootEl.style.display = active ? '' : 'none';
    }

    if (!active) {
      return;
    }

    if (this.isDirty || this.loadState.status === 'idle') {
      await this.refresh();
      return;
    }

    this.renderFilterBar();
    this.renderResults();
  }

  public invalidate(): void {
    this.isDirty = true;
    if (this.isActive) {
      void this.refresh();
    }
  }

  public destroy(): void {
    this.rootEl?.remove();
    this.rootEl = null;
    this.summaryHostEl = null;
    this.filterHostEl = null;
    this.resultsHostEl = null;
  }

  private async refresh(): Promise<void> {
    if (!this.rootEl) {
      return;
    }

    const activeToken = ++this.renderToken;
    this.isDirty = false;
    this.loadState = { status: 'loading' };
    this.renderSummaryLoading();
    this.renderFilterBar();
    this.renderResults();

    try {
      const snapshot = await this.callbacks.loadSnapshot();
      if (activeToken !== this.renderToken) {
        return;
      }

      const availableKeys = new Set(snapshot.inventory.catalog.components.map((component) => component.key));
      for (const expandedKey of Array.from(this.expandedKeys)) {
        if (!availableKeys.has(expandedKey)) {
          this.expandedKeys.delete(expandedKey);
        }
      }

      this.loadState = {
        snapshot,
        status: 'ready'
      };
      this.renderFilterBar();
      this.renderResults();
    } catch (error) {
      if (activeToken !== this.renderToken) {
        return;
      }

      const message = error instanceof Error && error.message.trim()
        ? error.message.trim()
        : 'Unable to load the component inventory.';
      this.loadState = {
        message,
        status: 'error'
      };
      this.renderSummaryError(message);
      this.renderResults();
    }
  }

  private renderFilterBar(): void {
    if (!this.filterHostEl) {
      return;
    }

    const snapshot = this.loadState.status === 'ready' ? this.loadState.snapshot : null;
    this.filterBar.render(this.filterHostEl, {
      availableFormats: snapshot?.inventory.catalog.formats ?? [],
      availableSourceFiles: snapshot?.inventory.catalog.sourceFiles ?? [],
      filters: this.filters
    });
  }

  private renderResults(): void {
    if (!this.resultsHostEl || !this.summaryHostEl) {
      return;
    }

    this.resultsHostEl.empty();

    if (this.loadState.status === 'loading' || this.loadState.status === 'idle') {
      this.renderSummaryLoading();
      this.renderStateCard({
        body: 'Scanning enabled SBOM files and merging parsed components.',
        title: 'Loading component inventory'
      });
      return;
    }

    if (this.loadState.status === 'error') {
      this.renderSummaryError(this.loadState.message);
      this.renderStateCard({
        body: this.loadState.message,
        tone: 'error',
        title: 'Component inventory unavailable'
      });
      return;
    }

    if (this.loadState.status !== 'ready') {
      return;
    }

    const { snapshot } = this.loadState;
    const inventory = snapshot.inventory;
    const derivedState = deriveComponentInventoryState(snapshot, this.filters);
    this.renderSummaryReady(inventory, derivedState.components.length, derivedState.summary);

    if (inventory.configuredSbomCount === 0) {
      this.renderStateCard({
        body: 'Add one or more SBOM files in the SBOM manager to build a merged component inventory.',
        title: 'No SBOM files configured'
      });
      return;
    }

    if (inventory.enabledSbomCount === 0) {
      this.renderStateCard({
        body: 'The configured SBOM files are all disabled. Enable at least one source to populate the inventory.',
        title: 'No enabled SBOM sources'
      });
      return;
    }

    if (inventory.catalog.componentCount === 0 && inventory.failedSbomCount > 0) {
      this.renderStateCard({
        body: 'Enabled SBOM files could not be parsed into a usable component inventory. Review the failures below and resync after fixing the source files.',
        tone: 'error',
        title: 'No components could be loaded'
      });
      this.renderIssues(inventory);
      return;
    }

    if (inventory.catalog.componentCount === 0) {
      this.renderStateCard({
        body: 'Enabled SBOM files were loaded, but no components were found.',
        title: 'No components detected'
      });
      return;
    }

    if (inventory.issues.length > 0) {
      this.renderIssues(inventory);
    }

    if (derivedState.components.length === 0) {
      this.renderStateCard({
        body: derivedState.hasActiveFilters
          ? 'Try broadening the current filters or clearing the search query.'
          : 'No components are available to display.',
        title: derivedState.hasActiveFilters ? 'No results matched the current filters' : 'No components available'
      });
      return;
    }

    this.renderTable(derivedState.components);
  }

  private renderSummaryLoading(): void {
    if (!this.summaryHostEl) {
      return;
    }

    this.summaryHostEl.empty();
    const grid = this.summaryHostEl.createDiv({ cls: 'vulndash-component-summary-grid' });
    this.createSummaryCard(grid, 'Components', '…');
    this.createSummaryCard(grid, 'Vulnerable', '…');
    this.createSummaryCard(grid, 'Followed', '…');
    this.createSummaryCard(grid, 'Enabled', '…');
  }

  private renderSummaryError(message: string): void {
    if (!this.summaryHostEl) {
      return;
    }

    this.summaryHostEl.empty();
    const banner = this.summaryHostEl.createDiv({ cls: 'vulndash-component-summary-banner is-error' });
    banner.createEl('strong', { text: 'Component inventory error' });
    banner.createEl('p', { text: message });
  }

  private renderSummaryReady(
    snapshot: ComponentInventorySnapshot,
    visibleCount: number,
    summary: {
      enabledCount: number;
      followedCount: number;
      totalCount: number;
      vulnerableCount: number;
    }
  ): void {
    if (!this.summaryHostEl) {
      return;
    }

    this.summaryHostEl.empty();

    const grid = this.summaryHostEl.createDiv({ cls: 'vulndash-component-summary-grid' });
    this.createSummaryCard(grid, 'Components', String(summary.totalCount), `${visibleCount} visible`);
    this.createSummaryCard(grid, 'Vulnerable', String(summary.vulnerableCount));
    this.createSummaryCard(grid, 'Followed', String(summary.followedCount));
    this.createSummaryCard(grid, 'Enabled', String(summary.enabledCount), `${snapshot.enabledSbomCount} active SBOM source${snapshot.enabledSbomCount === 1 ? '' : 's'}`);
  }

  private renderIssues(snapshot: ComponentInventorySnapshot): void {
    const issueCard = this.resultsHostEl?.createDiv({ cls: 'vulndash-component-issue-card vulndash-card-shell' });
    if (!issueCard) {
      return;
    }

    const heading = snapshot.catalog.componentCount > 0
      ? 'Some SBOM sources could not be refreshed'
      : 'Enabled SBOM sources failed to load';
    issueCard.createEl('h3', { text: heading });
    issueCard.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: snapshot.catalog.componentCount > 0
        ? 'The inventory below includes the SBOM data that was still readable or cached.'
        : 'No readable component inventory is available until at least one enabled SBOM parses successfully.'
    });

    const issueList = issueCard.createDiv({ cls: 'vulndash-component-issue-list' });
    for (const issue of snapshot.issues) {
      const item = issueList.createDiv({ cls: 'vulndash-component-issue-item' });
      item.createEl('strong', { text: issue.title });
      item.createDiv({
        cls: 'vulndash-muted-copy',
        text: issue.sourcePath ?? 'No source path configured'
      });
      item.createDiv({ text: issue.message });
      if (issue.hasCachedData) {
        item.createSpan({
          cls: 'vulndash-badge vulndash-badge-warning',
          text: 'Cached data shown'
        });
      }
    }
  }

  private renderTable(
    components: readonly ComponentInventoryDisplayEntry[]
  ): void {
    const tableShell = this.resultsHostEl?.createDiv({ cls: 'vulndash-component-table-shell vulndash-card-shell' });
    if (!tableShell) {
      return;
    }

    const table = tableShell.createEl('table', { cls: 'vulndash-component-table' });
    const head = table.createEl('thead');
    const headRow = head.createEl('tr');
    for (const label of ['Component', 'License', 'Identifier', 'Sources', 'Vulnerabilities', 'Actions']) {
      headRow.createEl('th', { text: label });
    }

    const body = table.createEl('tbody');
    for (const entry of components) {
      const { component } = entry;
      const rowCallbacks: ComponentRowRendererCallbacks = {
        detailsRenderer: this.callbacks.detailsRenderer,
        effectiveVulnerabilityCount: entry.vulnerabilityCount,
        onDisable: (trackedComponent) => {
          void this.handlePreferenceAction(trackedComponent.key, 'disable');
        },
        onEnable: (trackedComponent) => {
          void this.handlePreferenceAction(trackedComponent.key, 'enable');
        },
        onFollow: (trackedComponent) => {
          void this.handlePreferenceAction(trackedComponent.key, 'follow');
        },
        onToggleExpanded: (componentKey, expanded) => {
          if (expanded) {
            this.expandedKeys.add(componentKey);
          } else {
            this.expandedKeys.delete(componentKey);
          }
          this.renderResults();
        },
        onUnfollow: (trackedComponent) => {
          void this.handlePreferenceAction(trackedComponent.key, 'unfollow');
        }
      };
      if (entry.highestSeverity) {
        rowCallbacks.effectiveHighestSeverity = entry.highestSeverity;
      }

      if (this.callbacks.onOpenNote) {
        rowCallbacks.onOpenNote = this.callbacks.onOpenNote;
      }
      if (entry.relatedVulnerabilities.length > 0) {
        rowCallbacks.relatedVulnerabilities = entry.relatedVulnerabilities;
      }

      renderComponentRow(body, component, this.expandedKeys.has(component.key), rowCallbacks);
    }
  }

  private async handlePreferenceAction(
    componentKey: string,
    action: 'disable' | 'enable' | 'follow' | 'unfollow'
  ): Promise<void> {
    try {
      switch (action) {
        case 'disable':
          await this.callbacks.onDisableComponent(componentKey);
          break;
        case 'enable':
          await this.callbacks.onEnableComponent(componentKey);
          break;
        case 'follow':
          await this.callbacks.onFollowComponent(componentKey);
          break;
        case 'unfollow':
          await this.callbacks.onUnfollowComponent(componentKey);
          break;
        default:
          break;
      }

      await this.refresh();
    } catch (error) {
      const message = error instanceof Error && error.message.trim()
        ? error.message.trim()
        : 'Unable to update component preferences.';
      this.loadState = {
        message,
        status: 'error'
      };
      this.renderSummaryError(message);
      this.renderResults();
    }
  }

  private renderStateCard(copy: {
    body: string;
    title: string;
    tone?: 'error';
  }): void {
    const state = this.resultsHostEl?.createDiv({
      cls: `vulndash-empty-state vulndash-component-state${copy.tone === 'error' ? ' is-error' : ''}`
    });
    if (!state) {
      return;
    }

    state.createEl('h3', { text: copy.title });
    state.createEl('p', { text: copy.body });
  }

  private createSummaryCard(
    containerEl: HTMLElement,
    label: string,
    value: string,
    caption?: string
  ): void {
    const card = containerEl.createDiv({ cls: 'vulndash-component-summary-card vulndash-card-shell' });
    card.createDiv({ cls: 'vulndash-component-summary-label', text: label });
    card.createDiv({ cls: 'vulndash-component-summary-value', text: value });
    if (caption) {
      card.createDiv({ cls: 'vulndash-component-summary-caption', text: caption });
    }
  }
}
