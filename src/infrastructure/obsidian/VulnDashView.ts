import { ItemView, MarkdownRenderer, WorkspaceLeaf } from 'obsidian';
import type { ChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import { buildVulnerabilityCacheKey, createEmptyChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import type { ComponentInventoryWorkspaceSnapshot } from '../../application/sbom/types';
import type { DashboardSortOrder, VulnDashSettings } from '../../application/services/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { severityOrder } from '../../domain/entities/Severity';
import { ComponentInventoryView } from '../../ui/components/ComponentInventoryView';
import {
  type VulnerabilityRowColumn,
  type VulnerabilityRowColumnKey,
  VirtualizedVulnTable
} from '../../ui/components/VirtualizedVulnTable';

export const VULNDASH_VIEW_TYPE = 'vulndash-dashboard-view';

type SortKey = VulnerabilityRowColumnKey;
type VulnDashTab = 'components' | 'vulnerabilities';

const EMPTY_CHANGE_HINTS = createEmptyChangedVulnerabilityIds();

const compareStrings = (left: string, right: string): number => left.localeCompare(right);

const compareNumbers = (left: number, right: number): number => left - right;

const createSingleUpdatedHint = (key: string): ChangedVulnerabilityIds => ({
  added: [],
  removed: [],
  updated: [key]
});

export class VulnDashView extends ItemView {
  private activeTab: VulnDashTab = 'vulnerabilities';
  private componentWorkspaceDirty = true;
  private componentWorkspaceSnapshot: ComponentInventoryWorkspaceSnapshot | null = null;
  private readonly componentInventoryView: ComponentInventoryView;
  private componentPanelEl: HTMLDivElement | null = null;
  private readonly loadComponentInventory: () => Promise<ComponentInventoryWorkspaceSnapshot>;
  private localSearchQuery = '';
  private filterDebounceHandle: number | null = null;
  private maxResults = 100;
  private newItems = new Set<string>();
  private readonly openNotePath: (notePath: string) => Promise<void>;
  private pollingButton: HTMLButtonElement | null = null;
  private relatedComponentsByVulnerability: ComponentInventoryWorkspaceSnapshot['relationships']['componentsByVulnerability'] = new Map();
  private searchInputEl: HTMLInputElement | null = null;
  private sortDesc = true;
  private sortKey: SortKey = 'publishedAt';
  private tabButtons = new Map<VulnDashTab, HTMLButtonElement>();
  private colorCodedSeverity = true;
  private columnVisibility: VulnDashSettings['columnVisibility'] = {
    id: true,
    title: true,
    source: true,
    severity: true,
    cvssScore: true,
    publishedAt: true
  };
  private expandedItems = new Set<string>();
  private vulnerabilities: Vulnerability[] = [];
  private vulnerabilityPanelEl: HTMLDivElement | null = null;
  private vulnerabilityResultsEl: HTMLDivElement | null = null;
  private vulnerabilityRenderToken = 0;
  private vulnerabilityToolbarEl: HTMLDivElement | null = null;
  private readonly vulnerabilityTable: VirtualizedVulnTable;

  public constructor(
    leaf: WorkspaceLeaf,
    private readonly onRefresh: () => Promise<void>,
    private readonly onTogglePolling: () => Promise<void>,
    private readonly isPollingEnabled: () => boolean,
    inventoryCallbacks: {
      disableComponent: (componentKey: string) => Promise<void>;
      enableComponent: (componentKey: string) => Promise<void>;
      followComponent: (componentKey: string) => Promise<void>;
      loadComponentInventory: () => Promise<ComponentInventoryWorkspaceSnapshot>;
      openNotePath: (notePath: string) => Promise<void>;
      unfollowComponent: (componentKey: string) => Promise<void>;
    }
  ) {
    super(leaf);
    this.loadComponentInventory = inventoryCallbacks.loadComponentInventory;
    this.openNotePath = inventoryCallbacks.openNotePath;
    this.componentInventoryView = new ComponentInventoryView({
      loadSnapshot: async () => this.loadComponentWorkspaceSnapshot(this.loadComponentInventory),
      onDisableComponent: inventoryCallbacks.disableComponent,
      onEnableComponent: inventoryCallbacks.enableComponent,
      onFollowComponent: inventoryCallbacks.followComponent,
      onOpenNote: (notePath) => {
        void this.openNotePath(notePath);
      },
      onUnfollowComponent: inventoryCallbacks.unfollowComponent
    });
    this.vulnerabilityTable = new VirtualizedVulnTable({
      colorCodedSeverity: () => this.colorCodedSeverity,
      getRelatedComponents: (vulnerability) => {
        const vulnerabilityRef = `${vulnerability.source.trim().toLowerCase()}::${vulnerability.id.trim().toLowerCase()}`;
        return this.relatedComponentsByVulnerability.get(vulnerabilityRef) ?? [];
      },
      getRowKey: (vulnerability) => this.getVulnerabilityKey(vulnerability),
      isExpanded: (vulnerabilityKey) => this.expandedItems.has(vulnerabilityKey),
      isNew: (vulnerabilityKey) => this.newItems.has(vulnerabilityKey),
      onColumnSort: (columnKey) => {
        if (this.sortKey === columnKey) {
          this.sortDesc = !this.sortDesc;
        } else {
          this.sortKey = columnKey;
          this.sortDesc = true;
        }
        void this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
          forcePatchAll: false,
          reloadRelationships: false
        });
      },
      onToggleExpanded: (vulnerability, expanded) => {
        const vulnerabilityKey = this.getVulnerabilityKey(vulnerability);
        if (expanded) {
          this.expandedItems.add(vulnerabilityKey);
        } else {
          this.expandedItems.delete(vulnerabilityKey);
        }
        this.vulnerabilityTable.render(this.buildVulnerabilityTableState(), {
          changedIds: createSingleUpdatedHint(vulnerabilityKey),
          forcePatchAll: false
        });
      },
      renderSummary: async (vulnerability, containerEl) => this.renderSummaryIfNeeded(vulnerability, containerEl)
    });
  }

  public getViewType(): string {
    return VULNDASH_VIEW_TYPE;
  }

  public getDisplayText(): string {
    return 'VulnDash';
  }

  public override async onOpen(): Promise<void> {
    this.buildLayout();
    await this.renderActiveTab();
  }

  public override async onClose(): Promise<void> {
    if (this.filterDebounceHandle !== null) {
      window.clearTimeout(this.filterDebounceHandle);
      this.filterDebounceHandle = null;
    }
    this.componentInventoryView.destroy();
    this.vulnerabilityTable.destroy();
  }

  public setSettings(settings: VulnDashSettings): void {
    this.sortKey = this.getDefaultSort(settings.defaultSortOrder);
    this.sortDesc = true;
    this.maxResults = settings.maxResults;
    this.colorCodedSeverity = settings.colorCodedSeverity;
    this.columnVisibility = settings.columnVisibility;
    this.componentWorkspaceDirty = true;
    this.componentWorkspaceSnapshot = null;
    this.componentInventoryView.invalidate();

    if (this.activeTab === 'vulnerabilities') {
      void this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
        forcePatchAll: true,
        reloadRelationships: false
      });
      return;
    }

    void this.renderActiveTab();
  }

  public setPollingEnabled(_enabled: boolean): void {
    if (this.pollingButton !== null) {
      this.pollingButton.textContent = this.isPollingEnabled() ? 'Stop polling' : 'Start polling';
    }
  }

  public setData(
    vulnerabilities: Vulnerability[],
    changedIds: ChangedVulnerabilityIds = EMPTY_CHANGE_HINTS
  ): void {
    const hasChangeHints = changedIds.added.length > 0 || changedIds.updated.length > 0 || changedIds.removed.length > 0;
    const current = new Set(vulnerabilities.map((vulnerability) => this.getVulnerabilityKey(vulnerability)));

    this.newItems = new Set(Array.from(this.newItems).filter((key) => current.has(key)));
    if (hasChangeHints) {
      for (const key of changedIds.added) {
        this.newItems.add(key);
      }
    } else {
      const previous = new Set(this.vulnerabilities.map((vulnerability) => this.getVulnerabilityKey(vulnerability)));
      for (const vulnerability of vulnerabilities) {
        const key = this.getVulnerabilityKey(vulnerability);
        if (!previous.has(key)) {
          this.newItems.add(key);
        }
      }
    }

    this.expandedItems = new Set(Array.from(this.expandedItems).filter((id) => current.has(id)));
    this.vulnerabilities = vulnerabilities;
    this.componentWorkspaceDirty = true;
    this.componentWorkspaceSnapshot = null;
    this.componentInventoryView.invalidate();

    if (this.activeTab === 'vulnerabilities') {
      void this.refreshVulnerabilityTable(changedIds, {
        forcePatchAll: false,
        reloadRelationships: true
      });
    }
  }

  private buildLayout(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass('vulndash-view');

    const header = contentEl.createDiv({ cls: 'vulndash-header vulndash-header-stacked' });
    const titleBlock = header.createDiv({ cls: 'vulndash-header-title-block' });
    titleBlock.createEl('h2', { text: 'VulnDash' });
    titleBlock.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: 'Monitor live vulnerabilities and inspect merged SBOM components from the same workspace.'
    });

    const controls = header.createDiv({ cls: 'vulndash-controls' });
    const tabs = controls.createDiv({ cls: 'vulndash-tab-bar' });
    this.createTabButton(tabs, 'vulnerabilities', 'Vulnerabilities');
    this.createTabButton(tabs, 'components', 'Components');

    const buttonBar = controls.createDiv({ cls: 'vulndash-toolbar-buttons' });
    const pollingBtn = buttonBar.createEl('button', {
      text: this.isPollingEnabled() ? 'Stop polling' : 'Start polling'
    });
    this.pollingButton = pollingBtn;
    pollingBtn.addEventListener('click', () => {
      void this.onTogglePolling();
    });

    const refreshBtn = buttonBar.createEl('button', { text: 'Refresh now' });
    refreshBtn.addEventListener('click', () => {
      void this.onRefresh();
      this.componentInventoryView.invalidate();
    });

    this.vulnerabilityPanelEl = contentEl.createDiv({ cls: 'vulndash-vulnerability-panel' });
    this.vulnerabilityToolbarEl = this.vulnerabilityPanelEl.createDiv({ cls: 'vulndash-vulnerability-toolbar-host' });
    this.vulnerabilityResultsEl = this.vulnerabilityPanelEl.createDiv({ cls: 'vulndash-vulnerability-results' });
    this.mountVulnerabilityToolbar();
    this.vulnerabilityTable.mount(this.vulnerabilityResultsEl);

    this.componentPanelEl = contentEl.createDiv({ cls: 'vulndash-component-panel' });
    this.componentInventoryView.mount(this.componentPanelEl);
    this.updateTabButtons();
  }

  private buildVulnerabilityTableState(): {
    columns: readonly VulnerabilityRowColumn[];
    emptyState?: {
      body: string;
      title: string;
    };
    vulnerabilities: readonly Vulnerability[];
  } {
    const vulnerabilities = this.getFilteredVulnerabilities();
    const columns = this.getVisibleColumns();

    if (vulnerabilities.length === 0) {
      return {
        columns,
        emptyState: {
          body: this.localSearchQuery
            ? 'Try broadening the search query or clear the filter.'
            : 'Refresh the dashboard after configuring at least one enabled vulnerability source.',
          title: this.localSearchQuery ? 'No vulnerabilities match the current search' : 'No vulnerabilities available'
        },
        vulnerabilities
      };
    }

    return {
      columns,
      vulnerabilities
    };
  }

  private createTabButton(containerEl: HTMLElement, tab: VulnDashTab, label: string): void {
    const button = containerEl.createEl('button', { text: label });
    button.addClass('vulndash-tab-button');
    button.addEventListener('click', () => {
      this.activeTab = tab;
      this.updateTabButtons();
      void this.renderActiveTab();
    });
    this.tabButtons.set(tab, button);
  }

  private getDefaultSort(sortOrder: DashboardSortOrder): SortKey {
    if (sortOrder === 'cvssScore') {
      return 'cvssScore';
    }

    return 'publishedAt';
  }

  private getFilteredVulnerabilities(): Vulnerability[] {
    let data = this.getSorted().slice(0, this.maxResults);
    if (this.localSearchQuery) {
      data = data.filter((vulnerability) =>
        vulnerability.title.toLowerCase().includes(this.localSearchQuery)
        || vulnerability.id.toLowerCase().includes(this.localSearchQuery)
        || vulnerability.source.toLowerCase().includes(this.localSearchQuery)
      );
    }

    return data;
  }

  private getSorted(): Vulnerability[] {
    return [...this.vulnerabilities].sort((left, right) => {
      const comparison = this.compareVulnerabilities(left, right, this.sortKey);
      if (comparison !== 0) {
        return this.sortDesc ? -comparison : comparison;
      }

      return 0;
    });
  }

  private getVisibleColumns(): VulnerabilityRowColumn[] {
    const columns: VulnerabilityRowColumn[] = [
      { key: 'id', label: 'ID' },
      { key: 'title', label: 'Title' },
      { key: 'source', label: 'Source' },
      { key: 'severity', label: 'Severity' },
      { key: 'cvssScore', label: 'CVSS' },
      { key: 'publishedAt', label: 'Published' }
    ];

    return columns.filter((column) => this.columnVisibility[column.key]);
  }

  private getVulnerabilityKey(vulnerability: Vulnerability): string {
    return buildVulnerabilityCacheKey(vulnerability);
  }

  private async loadComponentWorkspaceSnapshot(
    loader: () => Promise<ComponentInventoryWorkspaceSnapshot>
  ): Promise<ComponentInventoryWorkspaceSnapshot> {
    if (!this.componentWorkspaceDirty && this.componentWorkspaceSnapshot) {
      return this.componentWorkspaceSnapshot;
    }

    const snapshot = await loader();
    this.componentWorkspaceSnapshot = snapshot;
    this.componentWorkspaceDirty = false;
    return snapshot;
  }

  private mountVulnerabilityToolbar(): void {
    if (!this.vulnerabilityToolbarEl || this.searchInputEl) {
      return;
    }

    const filterBar = this.vulnerabilityToolbarEl.createDiv({ cls: 'vulndash-vulnerability-toolbar vulndash-card-shell' });
    const searchField = filterBar.createDiv({ cls: 'vulndash-vulnerability-search' });
    searchField.createEl('label', { text: 'Search vulnerabilities' });
    this.searchInputEl = searchField.createEl('input', {
      attr: {
        placeholder: 'Filter by title, ID, or source',
        type: 'search'
      },
      cls: 'vulndash-search-bar'
    });
    this.searchInputEl.value = this.localSearchQuery;
    this.searchInputEl.addEventListener('input', (event) => {
      this.localSearchQuery = (event.target as HTMLInputElement).value.toLowerCase();
      if (this.filterDebounceHandle !== null) {
        window.clearTimeout(this.filterDebounceHandle);
      }
      this.filterDebounceHandle = window.setTimeout(() => {
        this.filterDebounceHandle = null;
        void this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
          forcePatchAll: false,
          reloadRelationships: false
        });
      }, 250);
    });
  }

  private compareVulnerabilities(left: Vulnerability, right: Vulnerability, sortKey: SortKey): number {
    const primary = (() => {
      switch (sortKey) {
        case 'severity':
          return compareNumbers(severityOrder[left.severity], severityOrder[right.severity]);
        case 'cvssScore':
          return compareNumbers(left.cvssScore, right.cvssScore);
        case 'id':
          return compareStrings(left.id, right.id);
        case 'source':
          return compareStrings(left.source, right.source);
        case 'title':
          return compareStrings(left.title, right.title);
        case 'publishedAt':
        default:
          return compareStrings(left.publishedAt, right.publishedAt);
      }
    })();

    if (primary !== 0) {
      return primary;
    }

    return compareStrings(this.getVulnerabilityKey(left), this.getVulnerabilityKey(right));
  }

  private async refreshVulnerabilityTable(
    changedIds: ChangedVulnerabilityIds = EMPTY_CHANGE_HINTS,
    options: {
      forcePatchAll: boolean;
      reloadRelationships: boolean;
    }
  ): Promise<void> {
    if (!this.vulnerabilityResultsEl) {
      return;
    }

    const activeToken = ++this.vulnerabilityRenderToken;
    const shouldLoadRelationships = options.reloadRelationships
      || (!this.componentWorkspaceSnapshot && this.componentWorkspaceDirty)
      || (this.relatedComponentsByVulnerability.size === 0 && this.vulnerabilities.length > 0);

    if (shouldLoadRelationships) {
      const componentWorkspaceSnapshot = await this.loadComponentWorkspaceSnapshot(this.loadComponentInventory);
      if (activeToken !== this.vulnerabilityRenderToken) {
        return;
      }
      this.relatedComponentsByVulnerability = componentWorkspaceSnapshot.relationships.componentsByVulnerability;
    }

    this.vulnerabilityTable.render(this.buildVulnerabilityTableState(), {
      changedIds,
      forcePatchAll: options.forcePatchAll
    });
  }

  private async renderActiveTab(): Promise<void> {
    if (!this.vulnerabilityPanelEl || !this.componentPanelEl) {
      return;
    }

    if (this.activeTab === 'vulnerabilities') {
      this.vulnerabilityPanelEl.style.display = '';
      this.componentPanelEl.style.display = 'none';
      await this.componentInventoryView.setActive(false);
      await this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
        forcePatchAll: false,
        reloadRelationships: this.componentWorkspaceDirty || this.componentWorkspaceSnapshot === null
      });
      return;
    }

    this.vulnerabilityPanelEl.style.display = 'none';
    this.componentPanelEl.style.display = '';
    await this.componentInventoryView.setActive(true);
  }

  private async renderSummaryIfNeeded(vulnerability: Vulnerability, container: HTMLDivElement): Promise<void> {
    if (!container.isConnected) {
      return;
    }

    const renderKey = `${this.getVulnerabilityKey(vulnerability)}::${vulnerability.summary}`;
    if (container.dataset.vulndashSummaryKey === renderKey && container.childElementCount > 0) {
      return;
    }

    container.dataset.vulndashSummaryKey = renderKey;
    container.empty();
    await MarkdownRenderer.render(this.app, vulnerability.summary, container, '', this);
    if (container.dataset.vulndashSummaryKey !== renderKey && container.isConnected) {
      container.empty();
    }
  }

  private updateTabButtons(): void {
    for (const [tab, button] of this.tabButtons) {
      button.toggleClass('is-active', tab === this.activeTab);
    }
  }
}

