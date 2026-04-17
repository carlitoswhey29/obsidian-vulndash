import type { ChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import type { RelatedComponentSummary } from '../../application/sbom/types';
import { createEmptyChangedVulnerabilityIds } from '../../application/pipeline/PipelineTypes';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { TriageState } from '../../domain/triage/TriageState';
import { buildRowPatchPlan } from '../rendering/RowPatchEngine';
import { RowRegistry } from '../rendering/RowRegistry';
import {
  areRelatedComponentsEqual,
  areVulnRowViewModelsEqual,
  buildVulnRowViewModel,
  type VulnRowViewModel,
  type VulnerabilityRowColumn,
  type VulnerabilityRowColumnKey
} from '../rendering/VulnRowViewModel';
import { calculateVirtualRange, type VirtualRange } from './VirtualRangeCalculator';
import { createTriageStateSelect, updateTriageStateSelect } from './TriageStatePill';
import { VirtualViewport, type VirtualViewportState } from './VirtualViewport';

export type { VulnerabilityRowColumn, VulnerabilityRowColumnKey } from '../rendering/VulnRowViewModel';

export interface VirtualizedVulnTableCallbacks {
  colorCodedSeverity: () => boolean;
  getRelatedComponents: (vulnerability: Vulnerability) => readonly RelatedComponentSummary[];
  getRowKey: (vulnerability: Vulnerability) => string;
  getTriageState: (vulnerability: Vulnerability) => TriageState;
  isExpanded: (vulnerabilityKey: string) => boolean;
  isNew: (vulnerabilityKey: string) => boolean;
  isTriagePending: (vulnerabilityKey: string) => boolean;
  onColumnSort: (columnKey: VulnerabilityRowColumnKey) => void;
  onTriageStateChange: (vulnerability: Vulnerability, state: TriageState) => void;
  onToggleExpanded: (vulnerability: Vulnerability, expanded: boolean) => void;
  renderSummary: (vulnerability: Vulnerability, containerEl: HTMLDivElement) => Promise<void>;
}

export interface VirtualizedVulnTableRenderState {
  columns: readonly VulnerabilityRowColumn[];
  emptyState?: {
    body: string;
    title: string;
  };
  vulnerabilities: readonly Vulnerability[];
}

interface MountedVulnerabilityRow {
  detailsCell: HTMLTableCellElement | null;
  detailsHeadingEl: HTMLHeadingElement | null;
  detailsRow: HTMLTableRowElement | null;
  expandIndicatorEl: HTMLSpanElement | null;
  idTextEl: HTMLSpanElement | null;
  mainRow: HTMLTableRowElement;
  referenceSectionEl: HTMLDivElement | null;
  relatedComponentsSectionEl: HTMLDivElement | null;
  severityCellEl: HTMLTableCellElement | null;
  sourceCellEl: HTMLTableCellElement | null;
  summaryEl: HTMLDivElement | null;
  titleCellEl: HTMLTableCellElement | null;
  publishedAtCellEl: HTMLTableCellElement | null;
  cvssCellEl: HTMLTableCellElement | null;
  triageSelectEl: HTMLSelectElement | null;
  viewModel: VulnRowViewModel;
  vulnerability: Vulnerability;
}

interface ReconcileOptions {
  dirtyKeys: ReadonlySet<string>;
  forcePatchAll: boolean;
}

const DEFAULT_ROW_HEIGHT = 76;
const DEFAULT_EXPANDED_ROW_HEIGHT = 360;
const OVERSCAN_ITEMS = 6;

const EMPTY_CHANGE_HINTS = createEmptyChangedVulnerabilityIds();

const setTextIfChanged = (element: HTMLElement, text: string): void => {
  if (element.textContent !== text) {
    element.textContent = text;
  }
};

const areColumnKeysEqual = (left: readonly VulnerabilityRowColumnKey[], right: readonly VulnerabilityRowColumnKey[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

const buildDirtyKeySet = (changedIds: ChangedVulnerabilityIds): Set<string> =>
  new Set([...changedIds.added, ...changedIds.updated]);

export class VirtualizedVulnTable {
  private currentRenderState: VirtualizedVulnTableRenderState = {
    columns: [],
    vulnerabilities: []
  };
  private emptyStateEl: HTMLDivElement | null = null;
  private headerSignature = '';
  private measurementFrameId: number | null = null;
  private renderVersion = 0;
  private readonly rowHeights = new Map<string, number>();
  private readonly rowRegistry = new RowRegistry<MountedVulnerabilityRow>();
  private rootEl: HTMLDivElement | null = null;
  private tableBodyEl: HTMLTableSectionElement | null = null;
  private tableHeadEl: HTMLTableSectionElement | null = null;
  private topSpacerRowEl: HTMLTableRowElement | null = null;
  private bottomSpacerRowEl: HTMLTableRowElement | null = null;
  private viewportEl: HTMLDivElement | null = null;
  private viewportState: VirtualViewportState = {
    scrollTop: 0,
    viewportHeight: 0,
    viewportWidth: 0
  };
  private readonly viewport = new VirtualViewport({
    onChange: (state) => {
      const widthChanged = this.viewportState.viewportWidth !== state.viewportWidth;
      this.viewportState = state;
      if (widthChanged) {
        this.rowHeights.clear();
      }
      this.reconcileVisibleRows({
        dirtyKeys: new Set<string>(),
        forcePatchAll: false
      });
    }
  });

  public constructor(
    private readonly callbacks: VirtualizedVulnTableCallbacks
  ) {}

  public mount(containerEl: HTMLElement): void {
    if (this.rootEl) {
      return;
    }

    this.rootEl = containerEl.createDiv({ cls: 'vulndash-virtual-table-root' });
    this.emptyStateEl = this.rootEl.createDiv({ cls: 'vulndash-empty-state vulndash-virtual-empty-state' });
    this.viewportEl = this.rootEl.createDiv({ cls: 'vulndash-table-container vulndash-virtual-viewport vulndash-card-shell' });
    const table = this.viewportEl.createEl('table', { cls: 'vulndash-table vulndash-virtual-table' });
    this.tableHeadEl = table.createEl('thead');
    this.tableBodyEl = table.createEl('tbody');
    this.topSpacerRowEl = this.createSpacerRow();
    this.bottomSpacerRowEl = this.createSpacerRow();
    this.tableBodyEl.append(this.topSpacerRowEl, this.bottomSpacerRowEl);
    this.viewport.bind(this.viewportEl);
    this.updateEmptyState();
  }

  public render(
    state: VirtualizedVulnTableRenderState,
    options: {
      changedIds?: ChangedVulnerabilityIds;
      forcePatchAll?: boolean;
    } = {}
  ): void {
    this.currentRenderState = state;
    this.pruneHeightCache(state.vulnerabilities);
    const headerChanged = this.renderHeader();
    this.updateEmptyState();

    if (state.vulnerabilities.length === 0) {
      this.clearMountedRows();
      this.updateSpacerRows(0, 0, Math.max(state.columns.length, 1));
      this.viewport.refresh();
      return;
    }

    this.reconcileVisibleRows({
      dirtyKeys: buildDirtyKeySet(options.changedIds ?? EMPTY_CHANGE_HINTS),
      forcePatchAll: headerChanged || (options.forcePatchAll ?? false)
    });
    this.viewport.refresh();
  }

  public destroy(): void {
    if (this.measurementFrameId !== null) {
      window.cancelAnimationFrame(this.measurementFrameId);
      this.measurementFrameId = null;
    }

    this.clearMountedRows();
    this.viewport.destroy();
    this.rowHeights.clear();
    this.rootEl?.remove();
    this.rootEl = null;
    this.emptyStateEl = null;
    this.tableBodyEl = null;
    this.tableHeadEl = null;
    this.topSpacerRowEl = null;
    this.bottomSpacerRowEl = null;
    this.viewportEl = null;
    this.headerSignature = '';
  }

  private clearMountedRows(): void {
    for (const mountedRow of this.rowRegistry.values()) {
      this.removeMountedRow(mountedRow);
    }
    this.rowRegistry.clear();
  }

  private createSpacerRow(): HTMLTableRowElement {
    const documentRef = this.tableBodyEl?.ownerDocument ?? document;
    const spacerRow = documentRef.createElement('tr');
    spacerRow.className = 'vulndash-virtual-spacer-row';
    const spacerCell = documentRef.createElement('td');
    spacerRow.append(spacerCell);
    return spacerRow;
  }

  private createTableCell(documentRef: Document): HTMLTableCellElement {
    return documentRef.createElement('td');
  }

  private getEstimatedRowHeight(vulnerability: Vulnerability): number {
    const key = this.callbacks.getRowKey(vulnerability);
    const measured = this.rowHeights.get(key);
    if (measured !== undefined) {
      return measured;
    }

    return this.callbacks.isExpanded(key) ? DEFAULT_EXPANDED_ROW_HEIGHT : DEFAULT_ROW_HEIGHT;
  }

  private pruneHeightCache(vulnerabilities: readonly Vulnerability[]): void {
    const availableKeys = new Set(vulnerabilities.map((vulnerability) => this.callbacks.getRowKey(vulnerability)));
    for (const key of this.rowHeights.keys()) {
      if (!availableKeys.has(key)) {
        this.rowHeights.delete(key);
      }
    }
  }

  private renderHeader(): boolean {
    if (!this.tableHeadEl) {
      return false;
    }

    const nextSignature = this.currentRenderState.columns.map((column) => column.key).join('|');
    if (nextSignature === this.headerSignature) {
      return false;
    }

    this.headerSignature = nextSignature;
    this.tableHeadEl.empty();
    const headRow = this.tableHeadEl.createEl('tr');

    for (const column of this.currentRenderState.columns) {
      const th = headRow.createEl('th', { text: column.label });
      th.addEventListener('click', () => {
        this.callbacks.onColumnSort(column.key);
      });
    }

    return true;
  }

  private updateEmptyState(): void {
    if (!this.emptyStateEl || !this.viewportEl) {
      return;
    }

    const emptyState = this.currentRenderState.emptyState;
    const isEmpty = this.currentRenderState.vulnerabilities.length === 0;
    this.emptyStateEl.empty();
    this.emptyStateEl.style.display = isEmpty ? '' : 'none';
    this.viewportEl.style.display = isEmpty ? 'none' : '';

    if (!isEmpty || !emptyState) {
      return;
    }

    this.emptyStateEl.createEl('h3', { text: emptyState.title });
    this.emptyStateEl.createEl('p', { text: emptyState.body });
  }

  private reconcileVisibleRows(options: ReconcileOptions): void {
    if (!this.tableBodyEl || !this.viewportEl || !this.topSpacerRowEl || !this.bottomSpacerRowEl) {
      return;
    }

    const { vulnerabilities } = this.currentRenderState;
    if (vulnerabilities.length === 0) {
      this.clearMountedRows();
      this.updateSpacerRows(0, 0, Math.max(this.currentRenderState.columns.length, 1));
      return;
    }

    const estimatedHeights = vulnerabilities.map((vulnerability) => this.getEstimatedRowHeight(vulnerability));
    const range = calculateVirtualRange({
      itemHeights: estimatedHeights,
      overscanItems: OVERSCAN_ITEMS,
      scrollTop: this.viewportState.scrollTop,
      viewportHeight: this.viewportState.viewportHeight
    });
    const maxScrollTop = Math.max(range.totalHeight - this.viewportState.viewportHeight, 0);
    if (this.viewportEl.scrollTop > maxScrollTop) {
      this.viewportEl.scrollTop = maxScrollTop;
      return;
    }

    const visibleVulnerabilities = vulnerabilities.slice(range.startIndex, range.endIndex + 1);
    const visibleKeys = visibleVulnerabilities.map((vulnerability) => this.callbacks.getRowKey(vulnerability));
    const plan = buildRowPatchPlan({
      currentKeys: this.rowRegistry.keys(),
      dirtyKeys: options.dirtyKeys,
      forcePatchAll: options.forcePatchAll,
      nextKeys: visibleKeys
    });
    const patchKeys = new Set(plan.patchKeys);

    for (const key of plan.removeKeys) {
      const mountedRow = this.rowRegistry.get(key);
      if (!mountedRow) {
        continue;
      }

      this.removeMountedRow(mountedRow);
      this.rowRegistry.delete(key);
    }

    const visibleRows: MountedVulnerabilityRow[] = [];
    for (const vulnerability of visibleVulnerabilities) {
      const key = this.callbacks.getRowKey(vulnerability);
      const viewModel = buildVulnRowViewModel(vulnerability, {
        colorCodedSeverity: this.callbacks.colorCodedSeverity(),
        columns: this.currentRenderState.columns,
        expanded: this.callbacks.isExpanded(key),
        getRowKey: this.callbacks.getRowKey,
        isNew: this.callbacks.isNew(key),
        relatedComponents: this.callbacks.getRelatedComponents(vulnerability),
        triagePending: this.callbacks.isTriagePending(key),
        triageState: this.callbacks.getTriageState(vulnerability)
      });
      const existingRow = this.rowRegistry.get(key);
      if (!existingRow) {
        const mountedRow = this.createMountedRow(vulnerability, viewModel);
        this.rowRegistry.set(key, mountedRow);
        this.moveMountedRowBefore(mountedRow, this.bottomSpacerRowEl);
        visibleRows.push(mountedRow);
        continue;
      }

      const shouldPatch = patchKeys.has(key) || !areVulnRowViewModelsEqual(existingRow.viewModel, viewModel);
      if (shouldPatch) {
        this.patchMountedRow(existingRow, vulnerability, viewModel);
      } else {
        existingRow.vulnerability = vulnerability;
      }
      this.moveMountedRowBefore(existingRow, this.bottomSpacerRowEl);
      visibleRows.push(existingRow);
    }

    this.updateSpacerRows(range.offsetTop, range.offsetBottom, Math.max(this.currentRenderState.columns.length, 1));
    this.scheduleMeasurement(visibleRows, range);
  }

  private createMountedRow(vulnerability: Vulnerability, viewModel: VulnRowViewModel): MountedVulnerabilityRow {
    const documentRef = this.tableBodyEl?.ownerDocument ?? document;
    const mountedRow: MountedVulnerabilityRow = {
      detailsCell: null,
      detailsHeadingEl: null,
      detailsRow: null,
      expandIndicatorEl: null,
      idTextEl: null,
      mainRow: documentRef.createElement('tr'),
      referenceSectionEl: null,
      relatedComponentsSectionEl: null,
      severityCellEl: null,
      sourceCellEl: null,
      summaryEl: null,
      titleCellEl: null,
      publishedAtCellEl: null,
      cvssCellEl: null,
      triageSelectEl: null,
      viewModel,
      vulnerability
    };
    mountedRow.mainRow.className = 'vulndash-row-main vulndash-item-boundary';
    mountedRow.mainRow.addEventListener('click', () => {
      this.callbacks.onToggleExpanded(mountedRow.vulnerability, !mountedRow.viewModel.expanded);
    });

    this.rebuildMainRow(mountedRow, viewModel);
    this.syncDetailsRow(mountedRow, vulnerability, viewModel, true);
    return mountedRow;
  }

  private moveMountedRowBefore(mountedRow: MountedVulnerabilityRow, anchorRow: HTMLTableRowElement): void {
    anchorRow.parentElement?.insertBefore(mountedRow.mainRow, anchorRow);
    if (mountedRow.detailsRow) {
      anchorRow.parentElement?.insertBefore(mountedRow.detailsRow, anchorRow);
    }
  }

  private patchMountedRow(
    mountedRow: MountedVulnerabilityRow,
    vulnerability: Vulnerability,
    nextViewModel: VulnRowViewModel
  ): void {
    const previousViewModel = mountedRow.viewModel;
    if (!areColumnKeysEqual(previousViewModel.columnKeys, nextViewModel.columnKeys)) {
      this.rebuildMainRow(mountedRow, nextViewModel);
    } else {
      this.patchMainRowCells(mountedRow, previousViewModel, nextViewModel);
    }

    this.syncDetailsRow(mountedRow, vulnerability, nextViewModel, false);
    mountedRow.vulnerability = vulnerability;
    mountedRow.viewModel = nextViewModel;
  }

  private patchMainRowCells(
    mountedRow: MountedVulnerabilityRow,
    previousViewModel: VulnRowViewModel,
    nextViewModel: VulnRowViewModel
  ): void {
    if (mountedRow.expandIndicatorEl) {
      setTextIfChanged(mountedRow.expandIndicatorEl, nextViewModel.expanded ? '[-]' : '[+]');
    }
    if (mountedRow.idTextEl) {
      setTextIfChanged(mountedRow.idTextEl, nextViewModel.idText);
      mountedRow.idTextEl.classList.toggle('vulndash-new', nextViewModel.isNew);
    }
    if (mountedRow.triageSelectEl) {
      updateTriageStateSelect(mountedRow.triageSelectEl, nextViewModel.triageState, nextViewModel.triagePending);
    }
    if (mountedRow.titleCellEl) {
      setTextIfChanged(mountedRow.titleCellEl, nextViewModel.titleText);
    }
    if (mountedRow.sourceCellEl) {
      setTextIfChanged(mountedRow.sourceCellEl, nextViewModel.sourceText);
    }
    if (mountedRow.severityCellEl) {
      setTextIfChanged(mountedRow.severityCellEl, nextViewModel.severityText);
      if (previousViewModel.severityClassName && previousViewModel.severityClassName !== nextViewModel.severityClassName) {
        mountedRow.severityCellEl.classList.remove(previousViewModel.severityClassName);
      }
      if (nextViewModel.severityClassName) {
        mountedRow.severityCellEl.classList.add(nextViewModel.severityClassName);
      }
    }
    if (mountedRow.cvssCellEl) {
      setTextIfChanged(mountedRow.cvssCellEl, nextViewModel.cvssText);
    }
    if (mountedRow.publishedAtCellEl) {
      setTextIfChanged(mountedRow.publishedAtCellEl, nextViewModel.publishedAtText);
    }
  }

  private rebuildMainRow(mountedRow: MountedVulnerabilityRow, viewModel: VulnRowViewModel): void {
    const documentRef = mountedRow.mainRow.ownerDocument;
    mountedRow.mainRow.textContent = '';
    mountedRow.expandIndicatorEl = null;
    mountedRow.idTextEl = null;
    mountedRow.titleCellEl = null;
    mountedRow.sourceCellEl = null;
    mountedRow.severityCellEl = null;
    mountedRow.cvssCellEl = null;
    mountedRow.publishedAtCellEl = null;

    for (const columnKey of viewModel.columnKeys) {
      switch (columnKey) {
        case 'id': {
          const idCell = this.createTableCell(documentRef);
          const indicator = documentRef.createElement('span');
          indicator.className = 'vulndash-expand-indicator';
          indicator.textContent = viewModel.expanded ? '[-]' : '[+]';
          idCell.append(indicator);

          const idText = documentRef.createElement('span');
          idText.textContent = viewModel.idText;
          idText.classList.toggle('vulndash-new', viewModel.isNew);
          idCell.append(idText);

          const triageSelect = createTriageStateSelect(documentRef, {
            disabled: viewModel.triagePending,
            onChange: (state) => {
              this.callbacks.onTriageStateChange(mountedRow.vulnerability, state);
            },
            state: viewModel.triageState
          });
          triageSelect.classList.add('vulndash-inline-triage');
          idCell.append(triageSelect);

          mountedRow.expandIndicatorEl = indicator;
          mountedRow.idTextEl = idText;
          mountedRow.triageSelectEl = triageSelect;
          mountedRow.mainRow.append(idCell);
          break;
        }
        case 'title': {
          const titleCell = this.createTableCell(documentRef);
          titleCell.className = 'vulndash-title markdown-preview-view';
          titleCell.textContent = viewModel.titleText;
          mountedRow.titleCellEl = titleCell;
          mountedRow.mainRow.append(titleCell);
          break;
        }
        case 'source': {
          const sourceCell = this.createTableCell(documentRef);
          sourceCell.textContent = viewModel.sourceText;
          mountedRow.sourceCellEl = sourceCell;
          mountedRow.mainRow.append(sourceCell);
          break;
        }
        case 'severity': {
          const severityCell = this.createTableCell(documentRef);
          severityCell.textContent = viewModel.severityText;
          if (viewModel.severityClassName) {
            severityCell.classList.add(viewModel.severityClassName);
          }
          mountedRow.severityCellEl = severityCell;
          mountedRow.mainRow.append(severityCell);
          break;
        }
        case 'cvssScore': {
          const cvssCell = this.createTableCell(documentRef);
          cvssCell.textContent = viewModel.cvssText;
          mountedRow.cvssCellEl = cvssCell;
          mountedRow.mainRow.append(cvssCell);
          break;
        }
        case 'publishedAt': {
          const publishedAtCell = this.createTableCell(documentRef);
          publishedAtCell.textContent = viewModel.publishedAtText;
          mountedRow.publishedAtCellEl = publishedAtCell;
          mountedRow.mainRow.append(publishedAtCell);
          break;
        }
        default:
          break;
      }
    }
  }

  private syncDetailsRow(
    mountedRow: MountedVulnerabilityRow,
    vulnerability: Vulnerability,
    viewModel: VulnRowViewModel,
    forceRefreshDetails: boolean
  ): void {
    if (!viewModel.expanded) {
      if (mountedRow.detailsRow) {
        mountedRow.detailsRow.remove();
      }
      mountedRow.detailsRow = null;
      mountedRow.detailsCell = null;
      mountedRow.detailsHeadingEl = null;
      mountedRow.summaryEl = null;
      mountedRow.referenceSectionEl = null;
      mountedRow.relatedComponentsSectionEl = null;
      return;
    }

    if (!mountedRow.detailsRow) {
      const documentRef = mountedRow.mainRow.ownerDocument;
      mountedRow.detailsRow = documentRef.createElement('tr');
      mountedRow.detailsRow.className = 'vulndash-row-details';
      mountedRow.detailsCell = documentRef.createElement('td');
      mountedRow.detailsRow.append(mountedRow.detailsCell);
      mountedRow.detailsHeadingEl = documentRef.createElement('h3');
      mountedRow.detailsHeadingEl.className = 'vulndash-details-title';
      mountedRow.detailsCell.append(mountedRow.detailsHeadingEl);
      mountedRow.summaryEl = documentRef.createElement('div');
      mountedRow.summaryEl.className = 'vulndash-summary markdown-preview-view';
      mountedRow.detailsCell.append(mountedRow.summaryEl);
      mountedRow.referenceSectionEl = documentRef.createElement('div');
      mountedRow.detailsCell.append(mountedRow.referenceSectionEl);
      mountedRow.relatedComponentsSectionEl = documentRef.createElement('div');
      mountedRow.detailsCell.append(mountedRow.relatedComponentsSectionEl);
    }

    if (!mountedRow.detailsRow || !mountedRow.detailsCell || !mountedRow.detailsHeadingEl || !mountedRow.summaryEl || !mountedRow.referenceSectionEl || !mountedRow.relatedComponentsSectionEl) {
      return;
    }

    mountedRow.detailsCell.colSpan = Math.max(viewModel.columnKeys.length, 1);
    setTextIfChanged(mountedRow.detailsHeadingEl, viewModel.titleText);

    const previousViewModel = mountedRow.viewModel;
    if (forceRefreshDetails || previousViewModel.summaryMarkdown !== viewModel.summaryMarkdown) {
      mountedRow.summaryEl.empty();
      void this.callbacks.renderSummary(vulnerability, mountedRow.summaryEl);
    }

    if (forceRefreshDetails || previousViewModel.referenceUrls.length !== viewModel.referenceUrls.length || previousViewModel.referenceUrls.some((reference, index) => reference !== viewModel.referenceUrls[index])) {
      this.renderReferenceSection(mountedRow.referenceSectionEl, viewModel.referenceUrls);
    }

    if (forceRefreshDetails || !areRelatedComponentsEqual(previousViewModel.relatedComponents, viewModel.relatedComponents)) {
      this.renderRelatedComponentsSection(mountedRow.relatedComponentsSectionEl, viewModel);
    }
  }

  private renderReferenceSection(containerEl: HTMLDivElement, references: readonly string[]): void {
    containerEl.empty();
    containerEl.createEl('strong', { text: 'References:' });
    containerEl.createEl('br');
    for (const reference of references) {
      const anchor = containerEl.createEl('a', { text: reference });
      anchor.href = reference;
      anchor.target = '_blank';
      anchor.rel = 'noopener noreferrer';
      containerEl.createEl('br');
    }
  }

  private renderRelatedComponentsSection(containerEl: HTMLDivElement, viewModel: VulnRowViewModel): void {
    containerEl.empty();
    containerEl.addClass('vulndash-related-components-section');
    containerEl.createEl('strong', { text: 'Related Components:' });

    if (viewModel.relatedComponents.length === 0) {
      containerEl.createEl('p', {
        cls: 'vulndash-muted-copy',
        text: 'No deterministic SBOM component matches were found for this vulnerability.'
      });
      return;
    }

    const list = containerEl.createDiv({ cls: 'vulndash-component-chip-list' });
    for (const component of viewModel.relatedComponents) {
      list.createSpan({
        cls: 'vulndash-badge vulndash-badge-neutral',
        text: `${component.label} (${component.evidence})`
      });
    }
  }

  private removeMountedRow(mountedRow: MountedVulnerabilityRow): void {
    mountedRow.mainRow.remove();
    mountedRow.detailsRow?.remove();
  }

  private scheduleMeasurement(
    visibleRows: readonly MountedVulnerabilityRow[],
    range: VirtualRange
  ): void {
    if (this.measurementFrameId !== null) {
      window.cancelAnimationFrame(this.measurementFrameId);
      this.measurementFrameId = null;
    }

    const renderVersion = ++this.renderVersion;
    this.measurementFrameId = window.requestAnimationFrame(() => {
      this.measurementFrameId = null;

      if (renderVersion !== this.renderVersion) {
        return;
      }

      let cacheChanged = false;
      for (const mountedRow of visibleRows) {
        if (!mountedRow.mainRow.isConnected) {
          continue;
        }

        const measuredHeight = Math.ceil(
          mountedRow.mainRow.getBoundingClientRect().height
          + (mountedRow.detailsRow?.getBoundingClientRect().height ?? 0)
        );
        const key = mountedRow.viewModel.key;
        if (Math.abs((this.rowHeights.get(key) ?? 0) - measuredHeight) > 1) {
          this.rowHeights.set(key, measuredHeight);
          cacheChanged = true;
        }
      }

      if (!cacheChanged) {
        return;
      }

      const nextHeights = this.currentRenderState.vulnerabilities.map((vulnerability) => this.getEstimatedRowHeight(vulnerability));
      const nextRange = calculateVirtualRange({
        itemHeights: nextHeights,
        overscanItems: OVERSCAN_ITEMS,
        scrollTop: this.viewportState.scrollTop,
        viewportHeight: this.viewportState.viewportHeight
      });

      if (
        nextRange.startIndex !== range.startIndex
        || nextRange.endIndex !== range.endIndex
        || Math.abs(nextRange.offsetTop - range.offsetTop) > 1
        || Math.abs(nextRange.offsetBottom - range.offsetBottom) > 1
      ) {
        this.reconcileVisibleRows({
          dirtyKeys: new Set<string>(),
          forcePatchAll: false
        });
      }
    });
  }

  private updateSpacerRows(offsetTop: number, offsetBottom: number, columnCount: number): void {
    for (const spacerRow of [this.topSpacerRowEl, this.bottomSpacerRowEl]) {
      const spacerCell = spacerRow?.firstElementChild;
      if (spacerCell instanceof HTMLTableCellElement) {
        spacerCell.colSpan = columnCount;
      }
    }

    const topCell = this.topSpacerRowEl?.firstElementChild;
    if (topCell instanceof HTMLElement) {
      topCell.style.height = `${Math.max(Math.ceil(offsetTop), 0)}px`;
    }
    const bottomCell = this.bottomSpacerRowEl?.firstElementChild;
    if (bottomCell instanceof HTMLElement) {
      bottomCell.style.height = `${Math.max(Math.ceil(offsetBottom), 0)}px`;
    }
  }
}






