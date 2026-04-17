import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { sanitizeText } from '../../infrastructure/utils/sanitize';
import { calculateVirtualRange, type VirtualRange } from './VirtualRangeCalculator';
import { VirtualViewport, type VirtualViewportState } from './VirtualViewport';

export type VulnerabilityTableColumnKey = 'cvssScore' | 'id' | 'publishedAt' | 'severity' | 'source' | 'title';

export interface VulnerabilityTableColumn {
  key: VulnerabilityTableColumnKey;
  label: string;
}

export interface VirtualizedVulnTableCallbacks {
  colorCodedSeverity: () => boolean;
  getRowKey: (vulnerability: Vulnerability) => string;
  isExpanded: (vulnerabilityKey: string) => boolean;
  isNew: (vulnerabilityKey: string) => boolean;
  onColumnSort: (columnKey: VulnerabilityTableColumnKey) => void;
  onToggleExpanded: (vulnerability: Vulnerability, expanded: boolean) => void;
  renderRelatedComponents: (containerEl: HTMLElement, vulnerability: Vulnerability) => void;
  renderSummary: (vulnerability: Vulnerability, containerEl: HTMLDivElement) => Promise<void>;
}

export interface VirtualizedVulnTableRenderState {
  columns: readonly VulnerabilityTableColumn[];
  emptyState?: {
    body: string;
    title: string;
  };
  vulnerabilities: readonly Vulnerability[];
}

export interface RenderedVulnerabilityRow {
  detailsRow: HTMLTableRowElement | null;
  mainRow: HTMLTableRowElement;
}

// Row heights are measured lazily because both the title cell and expanded markdown details
// can wrap unpredictably inside Obsidian pane widths. Virtualization therefore uses
// conservative estimates until a row is materialized instead of rendering hidden rows.
const DEFAULT_ROW_HEIGHT = 76;
const DEFAULT_EXPANDED_ROW_HEIGHT = 360;
const OVERSCAN_ITEMS = 6;

const createSpacerRow = (tableBodyEl: HTMLElement, columnCount: number, height: number): void => {
  if (height <= 0) {
    return;
  }

  const spacerRow = tableBodyEl.createEl('tr', { cls: 'vulndash-virtual-spacer-row' });
  const spacerCell = spacerRow.createEl('td', {
    attr: {
      colspan: String(Math.max(columnCount, 1))
    }
  });
  spacerCell.style.height = `${Math.max(Math.ceil(height), 0)}px`;
};

export const renderVulnerabilityRows = (
  tableBodyEl: HTMLElement,
  vulnerability: Vulnerability,
  columns: readonly VulnerabilityTableColumn[],
  expanded: boolean,
  callbacks: VirtualizedVulnTableCallbacks
): RenderedVulnerabilityRow => {
  const row = tableBodyEl.createEl('tr', { cls: 'vulndash-row-main vulndash-item-boundary' });
  const vulnerabilityKey = callbacks.getRowKey(vulnerability);

  for (const column of columns) {
    switch (column.key) {
      case 'id': {
        const idCell = row.createEl('td');
        idCell.createSpan({ text: expanded ? '[-]' : '[+]', cls: 'vulndash-expand-indicator' });
        const idText = idCell.createSpan({ text: sanitizeText(vulnerability.id) });
        if (callbacks.isNew(vulnerabilityKey)) {
          idText.addClass('vulndash-new');
        }
        break;
      }
      case 'title': {
        const titleCell = row.createEl('td', { text: sanitizeText(vulnerability.title), cls: 'vulndash-title' });
        titleCell.addClass('markdown-preview-view');
        break;
      }
      case 'source':
        row.createEl('td', { text: sanitizeText(vulnerability.source) });
        break;
      case 'severity': {
        const severityCell = row.createEl('td', { text: sanitizeText(vulnerability.severity) });
        if (callbacks.colorCodedSeverity()) {
          severityCell.addClass(`vulndash-${vulnerability.severity.toLowerCase()}`);
        }
        break;
      }
      case 'cvssScore':
        row.createEl('td', { text: vulnerability.cvssScore.toFixed(1) });
        break;
      case 'publishedAt':
        row.createEl('td', { text: new Date(vulnerability.publishedAt).toLocaleString() });
        break;
      default:
        break;
    }
  }

  row.addEventListener('click', () => {
    callbacks.onToggleExpanded(vulnerability, !expanded);
  });

  if (!expanded) {
    return {
      detailsRow: null,
      mainRow: row
    };
  }

  const detailsRow = tableBodyEl.createEl('tr', { cls: 'vulndash-row-details' });
  const detailsCell = detailsRow.createEl('td', {
    attr: {
      colspan: String(Math.max(columns.length, 1))
    }
  });
  detailsCell.createEl('h3', { text: sanitizeText(vulnerability.title), cls: 'vulndash-details-title' });

  const summaryEl = detailsCell.createDiv({ cls: 'vulndash-summary markdown-preview-view' });
  void callbacks.renderSummary(vulnerability, summaryEl);

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

  callbacks.renderRelatedComponents(detailsCell, vulnerability);

  return {
    detailsRow,
    mainRow: row
  };
};

export class VirtualizedVulnTable {
  private currentRenderState: VirtualizedVulnTableRenderState = {
    columns: [],
    vulnerabilities: []
  };
  private emptyStateEl: HTMLDivElement | null = null;
  private measurementFrameId: number | null = null;
  private renderVersion = 0;
  private readonly rowHeights = new Map<string, number>();
  private rootEl: HTMLDivElement | null = null;
  private tableBodyEl: HTMLTableSectionElement | null = null;
  private tableHeadEl: HTMLTableSectionElement | null = null;
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
      this.renderVisibleRows();
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
    this.viewport.bind(this.viewportEl);
    this.updateEmptyState();
  }

  public render(state: VirtualizedVulnTableRenderState): void {
    this.currentRenderState = state;
    this.pruneHeightCache(state.vulnerabilities);
    this.renderHeader();
    this.updateEmptyState();
    this.viewport.refresh();
    this.renderVisibleRows();
  }

  public destroy(): void {
    if (this.measurementFrameId !== null) {
      window.cancelAnimationFrame(this.measurementFrameId);
      this.measurementFrameId = null;
    }

    this.viewport.destroy();
    this.rowHeights.clear();
    this.rootEl?.remove();
    this.rootEl = null;
    this.emptyStateEl = null;
    this.tableBodyEl = null;
    this.tableHeadEl = null;
    this.viewportEl = null;
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

  private renderHeader(): void {
    if (!this.tableHeadEl) {
      return;
    }

    this.tableHeadEl.empty();
    const headRow = this.tableHeadEl.createEl('tr');

    for (const column of this.currentRenderState.columns) {
      const th = headRow.createEl('th', { text: column.label });
      th.addEventListener('click', () => {
        this.callbacks.onColumnSort(column.key);
      });
    }
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

  private renderVisibleRows(): void {
    if (!this.tableBodyEl || !this.viewportEl) {
      return;
    }

    const { vulnerabilities, columns } = this.currentRenderState;
    this.tableBodyEl.empty();

    if (vulnerabilities.length === 0) {
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

    const columnCount = Math.max(columns.length, 1);
    createSpacerRow(this.tableBodyEl, columnCount, range.offsetTop);

    const visibleRows: Array<{
      detailsRow: HTMLTableRowElement | null;
      mainRow: HTMLTableRowElement;
      vulnerability: Vulnerability;
    }> = [];
    const renderVersion = ++this.renderVersion;

    for (let index = range.startIndex; index <= range.endIndex; index += 1) {
      const vulnerability = vulnerabilities[index];
      if (!vulnerability) {
        continue;
      }

      const key = this.callbacks.getRowKey(vulnerability);
      const rendered = renderVulnerabilityRows(
        this.tableBodyEl,
        vulnerability,
        columns,
        this.callbacks.isExpanded(key),
        this.callbacks
      );
      visibleRows.push({
        detailsRow: rendered.detailsRow,
        mainRow: rendered.mainRow,
        vulnerability
      });
    }

    createSpacerRow(this.tableBodyEl, columnCount, range.offsetBottom);
    this.scheduleMeasurement(visibleRows, range, renderVersion);
  }

  private scheduleMeasurement(
    visibleRows: readonly {
      detailsRow: HTMLTableRowElement | null;
      mainRow: HTMLTableRowElement;
      vulnerability: Vulnerability;
    }[],
    range: VirtualRange,
    renderVersion: number
  ): void {
    if (this.measurementFrameId !== null) {
      window.cancelAnimationFrame(this.measurementFrameId);
      this.measurementFrameId = null;
    }

    this.measurementFrameId = window.requestAnimationFrame(() => {
      this.measurementFrameId = null;

      if (renderVersion !== this.renderVersion) {
        return;
      }

      let cacheChanged = false;
      for (const entry of visibleRows) {
        if (!entry.mainRow.isConnected) {
          continue;
        }

        const measuredHeight = Math.ceil(
          entry.mainRow.getBoundingClientRect().height
          + (entry.detailsRow?.getBoundingClientRect().height ?? 0)
        );
        const key = this.callbacks.getRowKey(entry.vulnerability);
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
        this.renderVisibleRows();
      }
    });
  }
}



