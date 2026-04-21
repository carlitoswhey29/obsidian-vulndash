import { ItemView, MarkdownRenderer, WorkspaceLeaf } from 'obsidian';
import type { ChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import { buildVulnerabilityCacheKey, createEmptyChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import { FilterByAffectedProject, type AffectedProjectFilter } from '../../application/correlation/FilterByAffectedProject';
import {
  DEFAULT_DASHBOARD_DATE_RANGE,
  cloneDashboardDateRangeSelection,
  filterVulnerabilitiesByDateWindow,
  resolveDashboardDateRangeSelection,
  type DashboardDateRangeSelection
} from '../../application/dashboard/PublishedDateWindow';
import type { ComponentInventoryWorkspaceSnapshot } from '../../application/sbom/types';
import type { TriageFilterMode } from '../../application/triage/FilterByTriageState';
import type { DashboardDateField, DashboardSortOrder, VulnDashSettings } from '../../application/use-cases/types';
import { RelationshipNormalizer } from '../../application/sbom/RelationshipNormalizer';
import {
  EMPTY_AFFECTED_PROJECT_RESOLUTION,
  type AffectedProjectResolution
} from '../../domain/correlation/AffectedProjectResolution';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { buildTriageCorrelationKeyForVulnerability } from '../../domain/triage/TriageCorrelation';
import type { TriageRecord } from '../../domain/triage/TriageRecord';
import { DEFAULT_TRIAGE_STATE, type TriageState } from '../../domain/triage/TriageState';
import { severityOrder } from '../../domain/value-objects/Severity';
import { ComponentDetailsRenderer } from '../components/ComponentDetailPanel';
import { ComponentInventoryView } from '../components/ComponentInventoryView';
import { TriageFilterControl } from '../components/TriageFilterControl';
import {
  type VulnerabilityRowColumn,
  type VulnerabilityRowColumnKey,
  VirtualizedVulnTable
} from '../components/VirtualizedVulnTable';

export const VULNDASH_VIEW_TYPE = 'vulndash-dashboard-view';

type SortKey = VulnerabilityRowColumnKey;
type VulnDashTab = 'components' | 'vulnerabilities';

interface VulnerabilityTriageViewState {
  readonly correlationKey: string;
  readonly record: TriageRecord | null;
  readonly state: TriageState;
}

const EMPTY_CHANGE_HINTS = createEmptyChangedVulnerabilityIds();
const ALL_AFFECTED_PROJECT_FILTER_VALUE = '__all__';
const UNMAPPED_AFFECTED_PROJECT_FILTER_VALUE = '__unmapped__';

const compareStrings = (left: string, right: string): number => left.localeCompare(right);

const compareNumbers = (left: number, right: number): number => left - right;

const createSingleUpdatedHint = (key: string): ChangedVulnerabilityIds => ({
  added: [],
  removed: [],
  updated: [key]
});

export class VulnDashView extends ItemView {
  private activeTab: VulnDashTab = 'vulnerabilities';
  private affectedProjectFilterValue = ALL_AFFECTED_PROJECT_FILTER_VALUE;
  private affectedProjectFilterSelectEl: HTMLSelectElement | null = null;
  private affectedProjectsByVulnerabilityRef = new Map<string, AffectedProjectResolution>();
  private componentWorkspaceDirty = true;
  private componentWorkspaceSnapshot: ComponentInventoryWorkspaceSnapshot | null = null;
  private readonly componentDetailsRenderer: ComponentDetailsRenderer;
  private readonly componentInventoryView: ComponentInventoryView;
  private componentPanelEl: HTMLDivElement | null = null;
  private customDateFromInputEl: HTMLInputElement | null = null;
  private customDateToInputEl: HTMLInputElement | null = null;
  private customDateRangeEl: HTMLDivElement | null = null;
  private dashboardDateField: DashboardDateField = 'modified';
  private dashboardDateFieldSelectEl: HTMLSelectElement | null = null;
  private dateRangeSelectEl: HTMLSelectElement | null = null;
  private dateRangeValidationEl: HTMLDivElement | null = null;
  private dateRangeSelection = cloneDashboardDateRangeSelection(DEFAULT_DASHBOARD_DATE_RANGE);
  private appliedDateRangeSelection = cloneDashboardDateRangeSelection(DEFAULT_DASHBOARD_DATE_RANGE);
  private readonly getTriageFilter: () => TriageFilterMode;
  private readonly getNow: () => Date;
  private readonly loadComponentInventory: () => Promise<ComponentInventoryWorkspaceSnapshot>;
  private localSearchQuery = '';
  private filterDebounceHandle: number | null = null;
  private maxResults = 100;
  private newItems = new Set<string>();
  private readonly onDashboardDateFieldChange: (field: DashboardDateField) => Promise<void>;
  private readonly onGenerateDailyRollup: () => Promise<void>;
  private readonly onTriageFilterChange: (triageFilter: TriageFilterMode) => Promise<void>;
  private readonly onTriageStateChange: (vulnerability: Vulnerability, state: TriageState) => Promise<void>;
  private readonly openNotePath: (notePath: string) => Promise<void>;
  private readonly pendingTriageRequestByKey = new Map<string, number>();
  private pollingButton: HTMLButtonElement | null = null;
  private relatedComponentsByVulnerability: ComponentInventoryWorkspaceSnapshot['relationships']['componentsByVulnerability'] = new Map();
  private searchInputEl: HTMLInputElement | null = null;
  private sortDesc = true;
  private sortKey: SortKey = 'publishedAt';
  private tabButtons = new Map<VulnDashTab, HTMLButtonElement>();
  private readonly triageByVulnerabilityKey = new Map<string, VulnerabilityTriageViewState>();
  private readonly affectedProjectFilter = new FilterByAffectedProject();
  private readonly relationshipNormalizer = new RelationshipNormalizer();
  private readonly triageFilterControl = new TriageFilterControl({
    onChange: (triageFilter) => {
      void this.onTriageFilterChange(triageFilter);
    }
  });
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
    callbacks: {
      disableComponent: (componentKey: string) => Promise<void>;
      enableComponent: (componentKey: string) => Promise<void>;
      followComponent: (componentKey: string) => Promise<void>;
      getDashboardDateField: () => DashboardDateField;
      getTriageFilter: () => TriageFilterMode;
      getNow?: () => Date;
      loadComponentInventory: () => Promise<ComponentInventoryWorkspaceSnapshot>;
      onDashboardDateFieldChange: (field: DashboardDateField) => Promise<void>;
      onGenerateDailyRollup: () => Promise<void>;
      onTriageFilterChange: (triageFilter: TriageFilterMode) => Promise<void>;
      onTriageStateChange: (vulnerability: Vulnerability, state: TriageState) => Promise<void>;
      openNotePath: (notePath: string) => Promise<void>;
      unfollowComponent: (componentKey: string) => Promise<void>;
    }
  ) {
    super(leaf);
    this.componentDetailsRenderer = new ComponentDetailsRenderer(this.app, '');
    this.addChild(this.componentDetailsRenderer);
    this.dashboardDateField = callbacks.getDashboardDateField();
    this.getTriageFilter = callbacks.getTriageFilter;
    this.getNow = callbacks.getNow ?? (() => new Date());
    this.loadComponentInventory = callbacks.loadComponentInventory;
    this.onDashboardDateFieldChange = callbacks.onDashboardDateFieldChange;
    this.onGenerateDailyRollup = callbacks.onGenerateDailyRollup;
    this.onTriageFilterChange = callbacks.onTriageFilterChange;
    this.onTriageStateChange = callbacks.onTriageStateChange;
    this.openNotePath = callbacks.openNotePath;
    this.componentInventoryView = new ComponentInventoryView({
      detailsRenderer: this.componentDetailsRenderer,
      loadSnapshot: async () => this.loadComponentWorkspaceSnapshot(this.loadComponentInventory),
      onDisableComponent: callbacks.disableComponent,
      onEnableComponent: callbacks.enableComponent,
      onFollowComponent: callbacks.followComponent,
      onOpenNote: (notePath) => {
        void this.openNotePath(notePath);
      },
      onUnfollowComponent: callbacks.unfollowComponent
    });
    this.vulnerabilityTable = new VirtualizedVulnTable({
      colorCodedSeverity: () => this.colorCodedSeverity,
      getAffectedProjectResolution: (vulnerability) => this.getAffectedProjectResolution(vulnerability),
      getRelatedComponents: (vulnerability) => {
        const vulnerabilityRef = `${vulnerability.source.trim().toLowerCase()}::${vulnerability.id.trim().toLowerCase()}`;
        return this.relatedComponentsByVulnerability.get(vulnerabilityRef) ?? [];
      },
      getRowKey: (vulnerability) => this.getVulnerabilityKey(vulnerability),
      getTriageState: (vulnerability) => this.getTriageStateSnapshot(vulnerability).state,
      isExpanded: (vulnerabilityKey) => this.expandedItems.has(vulnerabilityKey),
      isNew: (vulnerabilityKey) => this.newItems.has(vulnerabilityKey),
      isTriagePending: (vulnerabilityKey) => this.pendingTriageRequestByKey.has(vulnerabilityKey),
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
      onOpenAffectedProject: (notePath) => {
        void this.openNotePath(notePath);
      },
      onTriageStateChange: (vulnerability, state) => {
        void this.handleTriageStateChange(vulnerability, state);
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
    this.dashboardDateField = settings.dashboardDateField;
    this.colorCodedSeverity = settings.colorCodedSeverity;
    this.columnVisibility = settings.columnVisibility;
    this.triageFilterControl.setValue(settings.triageFilter);
    this.componentWorkspaceDirty = true;
    this.componentWorkspaceSnapshot = null;
    this.componentInventoryView.invalidate();
    this.syncDateRangeControls();

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
    triageByKey: ReadonlyMap<string, VulnerabilityTriageViewState>,
    affectedProjectsByVulnerabilityRef: ReadonlyMap<string, AffectedProjectResolution>,
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
    this.triageByVulnerabilityKey.clear();
    for (const [key, triageState] of triageByKey) {
      this.triageByVulnerabilityKey.set(key, triageState);
    }
    this.affectedProjectsByVulnerabilityRef = new Map(affectedProjectsByVulnerabilityRef);
    this.vulnerabilities = vulnerabilities;
    this.syncAffectedProjectFilterControl();
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
    /* Moved the tab buttons and the action buttons into a new container to allow for better layout control */
    const tabs = controls.createDiv({ cls: 'vulndash-tab-bar' });
    this.createTabButton(tabs, 'vulnerabilities', 'Vulnerabilities');
    this.createTabButton(tabs, 'components', 'Components');

    /* The action buttons are now in their own container with flex layout to keep them grouped together and right-aligned */
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

    const rollupBtn = buttonBar.createEl('button', { text: 'Generate Briefing' });
    rollupBtn.addEventListener('click', () => {
      void this.onGenerateDailyRollup();
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
    const hasInteractiveFilters = Boolean(this.localSearchQuery)
        || this.affectedProjectFilterValue !== ALL_AFFECTED_PROJECT_FILTER_VALUE
        || this.appliedDateRangeSelection.preset !== DEFAULT_DASHBOARD_DATE_RANGE.preset;
      return {
        columns,
        emptyState: {
          body: hasInteractiveFilters
            ? 'Try broadening the search query, adjusting the date range, or clearing filters.'
            : 'Refresh the dashboard after configuring at least one enabled vulnerability source.',
          title: hasInteractiveFilters ? 'No vulnerabilities match the current filters' : 'No vulnerabilities available'
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
    let data = this.getSorted();
    const dateRangeResolution = resolveDashboardDateRangeSelection(this.appliedDateRangeSelection, this.getNow());
    if (dateRangeResolution.window) {
      data = filterVulnerabilitiesByDateWindow(data, dateRangeResolution.window, this.dashboardDateField);
    }
    data = this.affectedProjectFilter.execute(
      data,
      this.getSelectedAffectedProjectFilter(),
      (vulnerability) => this.getAffectedProjectResolution(vulnerability)
    );

    if (this.localSearchQuery) {
      data = data.filter((vulnerability) =>
        vulnerability.title.toLowerCase().includes(this.localSearchQuery)
        || vulnerability.id.toLowerCase().includes(this.localSearchQuery)
        || vulnerability.source.toLowerCase().includes(this.localSearchQuery)
      );
    }

    return data.slice(0, this.maxResults);
  }

  private getAffectedProjectFilterOptions(): Array<{ label: string; value: string; }> {
    const projects = new Map<string, string>();
    let hasUnmapped = false;

    for (const resolution of this.affectedProjectsByVulnerabilityRef.values()) {
      if (resolution.unmappedSboms.length > 0) {
        hasUnmapped = true;
      }

      for (const project of resolution.affectedProjects) {
        projects.set(
          project.notePath,
          project.status === 'broken' ? `${project.displayName} (missing)` : project.displayName
        );
      }
    }

    const options = [{
      label: 'All projects',
      value: ALL_AFFECTED_PROJECT_FILTER_VALUE
    }];

    if (hasUnmapped) {
      options.push({
        label: 'Unmapped SBOM findings',
        value: UNMAPPED_AFFECTED_PROJECT_FILTER_VALUE
      });
    }

    for (const [notePath, label] of Array.from(projects.entries()).sort((left, right) =>
      left[1].localeCompare(right[1]) || left[0].localeCompare(right[0]))) {
      options.push({
        label,
        value: notePath
      });
    }

    return options;
  }

  private getAffectedProjectResolution(vulnerability: Vulnerability): AffectedProjectResolution {
    const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
    return this.affectedProjectsByVulnerabilityRef.get(vulnerabilityRef) ?? EMPTY_AFFECTED_PROJECT_RESOLUTION;
  }

  private getSelectedAffectedProjectFilter(): AffectedProjectFilter {
    if (this.affectedProjectFilterValue === ALL_AFFECTED_PROJECT_FILTER_VALUE) {
      return { kind: 'all' };
    }

    if (this.affectedProjectFilterValue === UNMAPPED_AFFECTED_PROJECT_FILTER_VALUE) {
      return { kind: 'unmapped' };
    }

    return {
      kind: 'project',
      notePath: this.affectedProjectFilterValue
    };
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

  private getTriageStateSnapshot(vulnerability: Vulnerability): VulnerabilityTriageViewState {
    const key = this.getVulnerabilityKey(vulnerability);
    const existing = this.triageByVulnerabilityKey.get(key);
    if (existing) {
      return existing;
    }

    return {
      correlationKey: buildTriageCorrelationKeyForVulnerability(vulnerability),
      record: null,
      state: DEFAULT_TRIAGE_STATE
    };
  }

  private async handleTriageStateChange(vulnerability: Vulnerability, state: TriageState): Promise<void> {
    const key = this.getVulnerabilityKey(vulnerability);
    const generation = (this.pendingTriageRequestByKey.get(key) ?? 0) + 1;
    const previousState = this.getTriageStateSnapshot(vulnerability);

    this.pendingTriageRequestByKey.set(key, generation);
    this.triageByVulnerabilityKey.set(key, {
      ...previousState,
      state
    });
    await this.refreshVulnerabilityTable(createSingleUpdatedHint(key), {
      forcePatchAll: false,
      reloadRelationships: false
    });

    try {
      await this.onTriageStateChange(vulnerability, state);
    } catch (error) {
      if (this.pendingTriageRequestByKey.get(key) === generation) {
        this.triageByVulnerabilityKey.set(key, previousState);
        await this.refreshVulnerabilityTable(createSingleUpdatedHint(key), {
          forcePatchAll: false,
          reloadRelationships: false
        });
      }
      console.warn('[vulndash.triage.update_failed]', error);
      return;
    } finally {
      if (this.pendingTriageRequestByKey.get(key) === generation) {
        this.pendingTriageRequestByKey.delete(key);
        await this.refreshVulnerabilityTable(createSingleUpdatedHint(key), {
          forcePatchAll: false,
          reloadRelationships: false
        });
      }
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

    const controlsRow = filterBar.createDiv({ cls: 'vulndash-vulnerability-toolbar-controls' });

    const dateField = controlsRow.createDiv({ cls: 'vulndash-triage-filter' });
    dateField.createEl('label', { text: 'Use' });
    this.dashboardDateFieldSelectEl = dateField.createEl('select', { cls: 'vulndash-triage-filter-select' });
    for (const option of [
      { label: 'Modified Time', value: 'modified' },
      { label: 'Published Time', value: 'published' }
    ] as const) {
      const optionEl = this.dashboardDateFieldSelectEl.createEl('option', { text: option.label });
      optionEl.value = option.value;
      optionEl.selected = option.value === this.dashboardDateField;
    }
    this.dashboardDateFieldSelectEl.addEventListener('change', (event) => {
      const field = (event.target as HTMLSelectElement).value as DashboardDateField;
      this.dashboardDateField = field;
      void this.onDashboardDateFieldChange(field);
      void this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
        forcePatchAll: false,
        reloadRelationships: false
      });
      this.syncDateRangeControls();
    });

    const dateRangeField = controlsRow.createDiv({ cls: 'vulndash-triage-filter' });
    dateRangeField.createEl('label', { text: 'Date range' });
    this.dateRangeSelectEl = dateRangeField.createEl('select', { cls: 'vulndash-triage-filter-select' });
    for (const option of [
      { label: 'Past Day', value: 'past_day' },
      { label: 'Past 3 Days', value: 'past_3_days' },
      { label: 'Past 7 Days', value: 'past_7_days' },
      { label: 'Custom Range', value: 'custom' }
    ] as const) {
      const optionEl = this.dateRangeSelectEl.createEl('option', { text: option.label });
      optionEl.value = option.value;
      optionEl.selected = option.value === this.dateRangeSelection.preset;
    }
    this.dateRangeSelectEl.addEventListener('change', (event) => {
      const preset = (event.target as HTMLSelectElement).value as DashboardDateRangeSelection['preset'];
      this.handleDateRangeSelectionChange({
        ...this.dateRangeSelection,
        preset
      });
    });

    this.customDateRangeEl = controlsRow.createDiv({ cls: 'vulndash-date-range-custom' });
    const customFromField = this.customDateRangeEl.createDiv({ cls: 'vulndash-date-range-field' });
    customFromField.createEl('label', { text: 'From' });
    this.customDateFromInputEl = customFromField.createEl('input', {
      cls: 'vulndash-search-bar',
      attr: { type: 'date' }
    });
    this.customDateFromInputEl.value = this.dateRangeSelection.customFrom ?? '';
    this.customDateFromInputEl.addEventListener('change', (event) => {
      this.handleDateRangeSelectionChange({
        ...this.dateRangeSelection,
        customFrom: (event.target as HTMLInputElement).value
      });
    });

    const customToField = this.customDateRangeEl.createDiv({ cls: 'vulndash-date-range-field' });
    customToField.createEl('label', { text: 'To' });
    this.customDateToInputEl = customToField.createEl('input', {
      cls: 'vulndash-search-bar',
      attr: { type: 'date' }
    });
    this.customDateToInputEl.value = this.dateRangeSelection.customTo ?? '';
    this.customDateToInputEl.addEventListener('change', (event) => {
      this.handleDateRangeSelectionChange({
        ...this.dateRangeSelection,
        customTo: (event.target as HTMLInputElement).value
      });
    });

    this.dateRangeValidationEl = filterBar.createDiv({ cls: 'vulndash-date-range-validation' });

    const affectedProjectField = controlsRow.createDiv({ cls: 'vulndash-triage-filter' });
    affectedProjectField.createEl('label', { text: 'Affected project' });
    this.affectedProjectFilterSelectEl = affectedProjectField.createEl('select', { cls: 'vulndash-triage-filter-select' });
    this.affectedProjectFilterSelectEl.addEventListener('change', (event) => {
      this.affectedProjectFilterValue = (event.target as HTMLSelectElement).value;
      void this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
        forcePatchAll: false,
        reloadRelationships: false
      });
    });
    this.syncAffectedProjectFilterControl();

    this.triageFilterControl.mount(controlsRow, this.getTriageFilter());
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

    this.syncDateRangeControls();
  }

  private syncAffectedProjectFilterControl(): void {
    if (!this.affectedProjectFilterSelectEl) {
      return;
    }

    const options = this.getAffectedProjectFilterOptions();
    const validValues = new Set(options.map((option) => option.value));
    if (!validValues.has(this.affectedProjectFilterValue)) {
      this.affectedProjectFilterValue = ALL_AFFECTED_PROJECT_FILTER_VALUE;
    }

    this.affectedProjectFilterSelectEl.empty();
    for (const option of options) {
      const optionEl = this.affectedProjectFilterSelectEl.createEl('option', { text: option.label });
      optionEl.value = option.value;
      optionEl.selected = option.value === this.affectedProjectFilterValue;
    }
  }

  private handleDateRangeSelectionChange(nextSelection: DashboardDateRangeSelection): void {
    this.dateRangeSelection = cloneDashboardDateRangeSelection(nextSelection);
    const resolution = resolveDashboardDateRangeSelection(this.dateRangeSelection, this.getNow());
    if (resolution.isValid) {
      this.appliedDateRangeSelection = cloneDashboardDateRangeSelection(this.dateRangeSelection);
      void this.refreshVulnerabilityTable(EMPTY_CHANGE_HINTS, {
        forcePatchAll: false,
        reloadRelationships: false
      });
    }

    this.syncDateRangeControls();
  }

  private syncDateRangeControls(): void {
    if (this.dashboardDateFieldSelectEl) {
      this.dashboardDateFieldSelectEl.value = this.dashboardDateField;
    }
    if (this.dateRangeSelectEl) {
      this.dateRangeSelectEl.value = this.dateRangeSelection.preset;
    }
    if (this.customDateFromInputEl) {
      this.customDateFromInputEl.value = this.dateRangeSelection.customFrom ?? '';
    }
    if (this.customDateToInputEl) {
      this.customDateToInputEl.value = this.dateRangeSelection.customTo ?? '';
    }

    const isCustom = this.dateRangeSelection.preset === 'custom';
    if (this.customDateRangeEl) {
      this.customDateRangeEl.toggleClass('is-visible', isCustom);
      this.customDateRangeEl.style.display = isCustom ? 'grid' : 'none';
    }

    if (!this.dateRangeValidationEl) {
      return;
    }

    const resolution = resolveDashboardDateRangeSelection(this.dateRangeSelection, this.getNow());
    if (isCustom && !resolution.isValid) {
      this.dateRangeValidationEl.textContent = resolution.validationMessage ?? 'Enter a valid custom date range.';
      this.dateRangeValidationEl.style.display = '';
      return;
    }

    this.dateRangeValidationEl.textContent = '';
    this.dateRangeValidationEl.style.display = 'none';
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
    const summary = typeof vulnerability.summary === 'string' ? vulnerability.summary.trim() : '';
    const renderKey = `${this.getVulnerabilityKey(vulnerability)}::${summary}`;

    const existingSummaryHost = container.querySelector<HTMLElement>(':scope > .vulndash-vulnerability-summary-markdown');

    if (container.dataset.vulndashSummaryKey === renderKey && existingSummaryHost !== null) {
      return;
    }

    container.dataset.vulndashSummaryKey = renderKey;

    if (existingSummaryHost !== null) {
      existingSummaryHost.remove();
    }

    const summaryHost = container.createDiv({
      cls: 'vulndash-vulnerability-summary-markdown markdown-rendered'
    });

    if (!summary) {
      summaryHost.createEl('p', {
        cls: 'vulndash-muted-copy',
        text: 'No vulnerability summary is available.'
      });
      return;
    }

    await MarkdownRenderer.render(this.app, summary, summaryHost, '', this);

    if (container.dataset.vulndashSummaryKey !== renderKey && container.isConnected) {
      summaryHost.remove();
    }
  }

  private updateTabButtons(): void {
    for (const [tab, button] of this.tabButtons) {
      button.toggleClass('is-active', tab === this.activeTab);
    }
  }
}





