import { ItemView, MarkdownRenderer, WorkspaceLeaf } from 'obsidian';
import type { ComponentInventoryWorkspaceSnapshot, RelatedComponentSummary } from '../../application/sbom/types';
import type { DashboardSortOrder, VulnDashSettings } from '../../application/services/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { severityOrder } from '../../domain/entities/Severity';
import { ComponentInventoryView } from '../../ui/components/ComponentInventoryView';
import { sanitizeText } from '../utils/sanitize';

export const VULNDASH_VIEW_TYPE = 'vulndash-dashboard-view';

type SortKey = 'publishedAt' | 'severity' | 'cvssScore' | 'id' | 'source' | 'title';
type VulnDashTab = 'components' | 'vulnerabilities';

export class VulnDashView extends ItemView {
  private activeTab: VulnDashTab = 'vulnerabilities';
  private componentWorkspaceDirty = true;
  private componentWorkspaceSnapshot: ComponentInventoryWorkspaceSnapshot | null = null;
  private readonly componentInventoryView: ComponentInventoryView;
  private componentPanelEl: HTMLDivElement | null = null;
  private vulnerabilityPanelEl: HTMLDivElement | null = null;
  private vulnerabilities: Vulnerability[] = [];
  private newItems = new Set<string>();
  private expandedItems = new Set<string>();
  private sortKey: SortKey = 'publishedAt';
  private sortDesc = true;
  private maxResults = 100;
  private colorCodedSeverity = true;
  private columnVisibility: VulnDashSettings['columnVisibility'] = {
    id: true,
    title: true,
    source: true,
    severity: true,
    cvssScore: true,
    publishedAt: true
  };
  private localSearchQuery = '';
  private filterDebounceHandle: number | null = null;
  private readonly loadComponentInventory: () => Promise<ComponentInventoryWorkspaceSnapshot>;
  private readonly openNotePath: (notePath: string) => Promise<void>;
  private pollingButton: HTMLButtonElement | null = null;
  private tabButtons = new Map<VulnDashTab, HTMLButtonElement>();
  private vulnerabilityRenderToken = 0;

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
    void this.renderActiveTab();
  }

  public setPollingEnabled(_enabled: boolean): void {
    if (this.pollingButton !== null) {
      this.pollingButton.textContent = this.isPollingEnabled() ? 'Stop polling' : 'Start polling';
    }
  }

  public setData(vulnerabilities: Vulnerability[]): void {
    const previous = new Set(this.vulnerabilities.map((vulnerability) => vulnerability.id));
    const current = new Set(vulnerabilities.map((vulnerability) => vulnerability.id));

    for (const vulnerability of vulnerabilities) {
      if (!previous.has(vulnerability.id)) {
        this.newItems.add(vulnerability.id);
      }
    }

    this.expandedItems = new Set(
      Array.from(this.expandedItems).filter((id) => current.has(id))
    );
    this.vulnerabilities = vulnerabilities;
    this.componentWorkspaceDirty = true;
    this.componentWorkspaceSnapshot = null;

    if (this.activeTab === 'vulnerabilities') {
      void this.renderVulnerabilityPanel();
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

    this.vulnerabilityPanelEl = contentEl.createDiv();
    this.componentPanelEl = contentEl.createDiv();
    this.componentInventoryView.mount(this.componentPanelEl);
    this.updateTabButtons();
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

  private updateTabButtons(): void {
    for (const [tab, button] of this.tabButtons) {
      button.toggleClass('is-active', tab === this.activeTab);
    }
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

  private async renderActiveTab(): Promise<void> {
    if (!this.vulnerabilityPanelEl || !this.componentPanelEl) {
      return;
    }

    if (this.activeTab === 'vulnerabilities') {
      this.vulnerabilityPanelEl.style.display = '';
      await this.componentInventoryView.setActive(false);
      await this.renderVulnerabilityPanel();
      return;
    }

    this.vulnerabilityPanelEl.style.display = 'none';
    await this.componentInventoryView.setActive(true);
  }

  private getDefaultSort(sortOrder: DashboardSortOrder): SortKey {
    if (sortOrder === 'cvssScore') {
      return 'cvssScore';
    }

    return 'publishedAt';
  }

  private async renderVulnerabilityPanel(): Promise<void> {
    if (!this.vulnerabilityPanelEl) {
      return;
    }

    const activeToken = ++this.vulnerabilityRenderToken;
    const componentWorkspaceSnapshot = await this.loadComponentWorkspaceSnapshot(this.loadComponentInventory);
    if (activeToken !== this.vulnerabilityRenderToken) {
      return;
    }
    this.vulnerabilityPanelEl.empty();

    const filterBar = this.vulnerabilityPanelEl.createDiv({ cls: 'vulndash-vulnerability-toolbar vulndash-card-shell' });
    const searchField = filterBar.createDiv({ cls: 'vulndash-vulnerability-search' });
    searchField.createEl('label', { text: 'Search vulnerabilities' });
    const searchInput = searchField.createEl('input', {
      attr: {
        placeholder: 'Filter by title, ID, or source',
        type: 'search'
      },
      cls: 'vulndash-search-bar'
    });
    searchInput.value = this.localSearchQuery;
    searchInput.addEventListener('input', (event) => {
      this.localSearchQuery = (event.target as HTMLInputElement).value.toLowerCase();
      if (this.filterDebounceHandle !== null) {
        window.clearTimeout(this.filterDebounceHandle);
      }
      this.filterDebounceHandle = window.setTimeout(() => {
        this.filterDebounceHandle = null;
        void this.renderVulnerabilityPanel();
      }, 250);
    });

    const tableContainer = this.vulnerabilityPanelEl.createDiv({ cls: 'vulndash-table-container' });
    const table = tableContainer.createEl('table', { cls: 'vulndash-table' });
    const thead = table.createEl('thead');
    const headRow = thead.createEl('tr');

    const columns: Array<{ key: SortKey; label: string; visible: boolean }> = [
      { key: 'id', label: 'ID', visible: this.columnVisibility.id },
      { key: 'title', label: 'Title', visible: this.columnVisibility.title },
      { key: 'source', label: 'Source', visible: this.columnVisibility.source },
      { key: 'severity', label: 'Severity', visible: this.columnVisibility.severity },
      { key: 'cvssScore', label: 'CVSS', visible: this.columnVisibility.cvssScore },
      { key: 'publishedAt', label: 'Published', visible: this.columnVisibility.publishedAt }
    ];
    const visibleColumns = columns.filter((column) => column.visible);

    for (const column of visibleColumns) {
      const th = headRow.createEl('th', { text: column.label });
      th.addEventListener('click', () => {
        if (this.sortKey === column.key) {
          this.sortDesc = !this.sortDesc;
        } else {
          this.sortKey = column.key;
          this.sortDesc = true;
        }
        void this.renderVulnerabilityPanel();
      });
    }

    const tbody = table.createEl('tbody');

    let data = this.getSorted().slice(0, this.maxResults);
    if (this.localSearchQuery) {
      data = data.filter((vulnerability) =>
        vulnerability.title.toLowerCase().includes(this.localSearchQuery)
        || vulnerability.id.toLowerCase().includes(this.localSearchQuery)
        || vulnerability.source.toLowerCase().includes(this.localSearchQuery)
      );
    }

    if (data.length === 0) {
      const empty = this.vulnerabilityPanelEl.createDiv({ cls: 'vulndash-empty-state' });
      empty.createEl('h3', { text: this.localSearchQuery ? 'No vulnerabilities match the current search' : 'No vulnerabilities available' });
      empty.createEl('p', {
        text: this.localSearchQuery
          ? 'Try broadening the search query or clear the filter.'
          : 'Refresh the dashboard after configuring at least one enabled vulnerability source.'
      });
      return;
    }

    for (const vulnerability of data) {
      if (activeToken !== this.vulnerabilityRenderToken) {
        return;
      }

      const row = tbody.createEl('tr', { cls: 'vulndash-row-main vulndash-item-boundary' });

      for (const column of visibleColumns) {
        if (column.key === 'id') {
          const idCell = row.createEl('td');
          const isExpanded = this.expandedItems.has(vulnerability.id);
          idCell.createSpan({ text: isExpanded ? '[-]' : '[+]', cls: 'vulndash-expand-indicator' });
          const idText = idCell.createSpan({ text: sanitizeText(vulnerability.id) });
          if (this.newItems.has(vulnerability.id)) {
            idText.addClass('vulndash-new');
          }
        }
        if (column.key === 'title') {
          const titleCell = row.createEl('td', { text: sanitizeText(vulnerability.title), cls: 'vulndash-title' });
          titleCell.addClass('markdown-preview-view');
        }
        if (column.key === 'source') {
          row.createEl('td', { text: sanitizeText(vulnerability.source) });
        }
        if (column.key === 'severity') {
          const severityCell = row.createEl('td', { text: sanitizeText(vulnerability.severity) });
          if (this.colorCodedSeverity) {
            severityCell.addClass(`vulndash-${vulnerability.severity.toLowerCase()}`);
          }
        }
        if (column.key === 'cvssScore') {
          row.createEl('td', { text: vulnerability.cvssScore.toFixed(1) });
        }
        if (column.key === 'publishedAt') {
          row.createEl('td', { text: new Date(vulnerability.publishedAt).toLocaleString() });
        }
      }

      const details = tbody.createEl('tr', { cls: 'vulndash-row-details' });
      const isExpanded = this.expandedItems.has(vulnerability.id);
      details.style.display = isExpanded ? 'table-row' : 'none';

      const detailsCell = details.createEl('td', { attr: { colspan: String(Math.max(visibleColumns.length, 1)) } });
      detailsCell.createEl('h3', { text: sanitizeText(vulnerability.title), cls: 'vulndash-details-title' });

      const summaryEl = detailsCell.createDiv({ cls: 'vulndash-summary markdown-preview-view' });
      if (isExpanded) {
        await this.renderSummaryIfNeeded(vulnerability, summaryEl);
      }

      const refs = detailsCell.createDiv();
      refs.createEl('strong', { text: 'References:' });
      refs.createEl('br');
      for (const ref of vulnerability.references.slice(0, 3)) {
        const anchor = refs.createEl('a', { text: ref });
        anchor.href = ref;
        anchor.target = '_blank';
        anchor.rel = 'noopener noreferrer';
        refs.createEl('br');
      }

      this.renderRelatedComponents(
        detailsCell,
        vulnerability,
        componentWorkspaceSnapshot.relationships.componentsByVulnerability
      );

      row.addEventListener('click', () => {
        const isHidden = details.style.display === 'none';
        details.style.display = isHidden ? 'table-row' : 'none';
        if (isHidden) {
          this.expandedItems.add(vulnerability.id);
          void this.renderSummaryIfNeeded(vulnerability, summaryEl);
        } else {
          this.expandedItems.delete(vulnerability.id);
        }

        const indicator = row.querySelector('.vulndash-expand-indicator');
        if (indicator) {
          indicator.textContent = isHidden ? '[-]' : '[+]';
        }
      });
    }
  }

  private async renderSummaryIfNeeded(vulnerability: Vulnerability, container: HTMLDivElement): Promise<void> {
    if (container.childElementCount > 0) {
      return;
    }

    await MarkdownRenderer.render(this.app, vulnerability.summary, container, '', this);
  }

  private renderRelatedComponents(
    containerEl: HTMLElement,
    vulnerability: Vulnerability,
    componentsByVulnerability: ReadonlyMap<string, RelatedComponentSummary[]>
  ): void {
    const vulnerabilityRef = `${vulnerability.source.trim().toLowerCase()}::${vulnerability.id.trim().toLowerCase()}`;
    const relatedComponents = componentsByVulnerability.get(vulnerabilityRef) ?? [];

    const section = containerEl.createDiv({ cls: 'vulndash-related-components-section' });
    section.createEl('strong', { text: 'Related Components:' });

    if (relatedComponents.length === 0) {
      section.createEl('p', {
        cls: 'vulndash-muted-copy',
        text: 'No deterministic SBOM component matches were found for this vulnerability.'
      });
      return;
    }

    const list = section.createDiv({ cls: 'vulndash-component-chip-list' });
    for (const component of relatedComponents) {
      const label = component.version ? `${component.name} ${component.version}` : component.name;
      list.createSpan({
        cls: 'vulndash-badge vulndash-badge-neutral',
        text: `${label} (${component.evidence})`
      });
    }
  }

  private getSorted(): Vulnerability[] {
    const sorted = [...this.vulnerabilities].sort((left, right) => {
      switch (this.sortKey) {
        case 'severity':
          return severityOrder[left.severity] - severityOrder[right.severity];
        case 'cvssScore':
          return left.cvssScore - right.cvssScore;
        case 'id':
          return left.id.localeCompare(right.id);
        case 'source':
          return left.source.localeCompare(right.source);
        case 'publishedAt':
        default:
          return left.publishedAt.localeCompare(right.publishedAt);
      }
    });

    return this.sortDesc ? sorted.reverse() : sorted;
  }
}
