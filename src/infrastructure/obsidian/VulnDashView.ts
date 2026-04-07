import { ItemView, MarkdownRenderer, WorkspaceLeaf } from 'obsidian';
import type { DashboardSortOrder, VulnDashSettings } from '../../application/services/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { severityOrder } from '../../domain/entities/Severity';
import { sanitizeText } from '../utils/sanitize';

export const VULNDASH_VIEW_TYPE = 'vulndash-dashboard-view';

type SortKey = 'publishedAt' | 'severity' | 'cvssScore' | 'id' | 'source';

export class VulnDashView extends ItemView {
  private vulnerabilities: Vulnerability[] = [];
  private newItems = new Set<string>();
  private sortKey: SortKey = 'publishedAt';
  private sortDesc = true;
  private maxResults = 100; // Default value, will be overridden by settings
  private colorCodedSeverity = true;
  private columnVisibility: VulnDashSettings['columnVisibility'] = {
    id: true,
    source: true,
    severity: true,
    cvssScore: true,
    publishedAt: true
  };
  private localSearchQuery = '';
  private readonly onRefresh: () => Promise<void>;

  public constructor(leaf: WorkspaceLeaf, onRefresh: () => Promise<void>) {
    super(leaf);
    this.onRefresh = onRefresh;
  }

  public getViewType(): string {
    return VULNDASH_VIEW_TYPE;
  }

  public getDisplayText(): string {
    return 'VulnDash';
  }

  public override async onOpen(): Promise<void> {
    this.render();
  }

  public setSettings(settings: VulnDashSettings): void {
    this.sortKey = this.getDefaultSort(settings.defaultSortOrder);
    this.sortDesc = true;
    this.maxResults = settings.maxResults;
    this.colorCodedSeverity = settings.colorCodedSeverity;
    this.columnVisibility = settings.columnVisibility;
    this.render();
  }

  public setData(vulnerabilities: Vulnerability[]): void {
    const previous = new Set(this.vulnerabilities.map((v) => v.id));
    for (const vuln of vulnerabilities) {
      if (!previous.has(vuln.id)) {
        this.newItems.add(vuln.id);
      }
    }
    this.vulnerabilities = vulnerabilities;
    this.render();
  }

  private getDefaultSort(sortOrder: DashboardSortOrder): SortKey {
    if (sortOrder === 'cvssScore') {
      return 'cvssScore';
    }

    return 'publishedAt';
  }

  private render(): void {
    void this.renderAsync();
  }

  private async renderAsync(): Promise<void> {
    const { contentEl } = this;
    contentEl.empty();

    // 1. Header & Quick Filter Search Bar
    const header = contentEl.createDiv({ cls: 'vulndash-header' });
    header.createEl('h2', { text: 'VulnDash Dashboard' });

    const controls = header.createDiv({ cls: 'vulndash-controls' });

    const searchInput = controls.createEl('input', {
      type: 'text',
      placeholder: 'Filter results...',
      cls: 'vulndash-search-bar'
    });
    searchInput.value = this.localSearchQuery;
    searchInput.addEventListener('input', (e) => {
      this.localSearchQuery = (e.target as HTMLInputElement).value.toLowerCase();
      this.render(); // Re-render table on type
    });

    const refreshBtn = controls.createEl('button', { text: 'Refresh now' });
    refreshBtn.addEventListener('click', () => {
      void this.onRefresh();
    });

    // 2. Table Setup
    const table = contentEl.createEl('table', { cls: 'vulndash-table' });
    const thead = table.createEl('thead');
    const headRow = thead.createEl('tr');

    const columns: Array<{ key: SortKey; label: string; visible: boolean }> = [
      { key: 'id', label: 'ID', visible: this.columnVisibility.id },
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
        this.render();
      });
    }

    const tbody = table.createEl('tbody');

    // 3. Apply Local Search Filter
    let data = this.getSorted().slice(0, this.maxResults);
    if (this.localSearchQuery) {
      data = data.filter(v =>
        v.title.toLowerCase().includes(this.localSearchQuery) ||
        v.id.toLowerCase().includes(this.localSearchQuery) ||
        v.source.toLowerCase().includes(this.localSearchQuery)
      );
    }

    // 4. Render Rows with Folding Logic
    for (const vuln of data) {
      // Main Row
      const row = tbody.createEl('tr', { cls: 'vulndash-row-main vulndash-item-boundary' });

      for (const column of visibleColumns) {
        if (column.key === 'id') {
          const idCell = row.createEl('td');
          // Add fold indicator
          idCell.createSpan({ text: '[+]', cls: 'vulndash-expand-indicator' });
          const idText = idCell.createSpan({ text: sanitizeText(vuln.id) });

          if (this.newItems.has(vuln.id)) {
            idText.addClass('vulndash-new');
          }
        }
        if (column.key === 'source') {
          row.createEl('td', { text: sanitizeText(vuln.source) });
        }
        if (column.key === 'severity') {
          const sev = row.createEl('td', { text: sanitizeText(vuln.severity) });
          if (this.colorCodedSeverity && vuln.severity === 'CRITICAL') sev.addClass('vulndash-critical');
          if (this.colorCodedSeverity && vuln.severity === 'HIGH') sev.addClass('vulndash-high');
        }
        if (column.key === 'cvssScore') {
          row.createEl('td', { text: vuln.cvssScore.toFixed(1) });
        }
        if (column.key === 'publishedAt') {
          row.createEl('td', { text: new Date(vuln.publishedAt).toLocaleString() });
        }
      }

      // Details Row
      const details = tbody.createEl('tr', { cls: 'vulndash-row-details' });
      details.style.display = 'none'; // Hidden by default

      const detailsCell = details.createEl('td', { attr: { colspan: String(Math.max(visibleColumns.length, 1)) } });
      detailsCell.createEl('h3', { text: sanitizeText(vuln.title), cls: 'vulndash-details-title' });

      const summaryEl = detailsCell.createDiv({ cls: 'vulndash-summary' });
      // Add markdown-preview-view class so Obsidian knows to format it like standard markdown
      summaryEl.addClass('markdown-preview-view');
      await MarkdownRenderer.render(this.app, vuln.summary, summaryEl, '', this);

      const refs = detailsCell.createDiv();
      refs.createEl('strong', { text: 'References:' });
      refs.createEl('br');
      for (const ref of vuln.references.slice(0, 3)) {
        const a = refs.createEl('a', { text: ref });
        a.href = ref;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        refs.createEl('br');
      }

      // Interaction Logic
      row.addEventListener('click', () => {
        const isHidden = details.style.display === 'none';
        details.style.display = isHidden ? 'table-row' : 'none';

        const indicator = row.querySelector('.vulndash-expand-indicator');
        if (indicator) {
          indicator.textContent = isHidden ? '[-]' : '[+]';
        }
      });
    }
  }

  private getSorted(): Vulnerability[] {
    const sorted = [...this.vulnerabilities].sort((a, b) => {
      switch (this.sortKey) {
        case 'severity':
          return severityOrder[a.severity] - severityOrder[b.severity];
        case 'cvssScore':
          return a.cvssScore - b.cvssScore;
        case 'id':
          return a.id.localeCompare(b.id);
        case 'source':
          return a.source.localeCompare(b.source);
        case 'publishedAt':
        default:
          return a.publishedAt.localeCompare(b.publishedAt);
      }
    });

    return this.sortDesc ? sorted.reverse() : sorted;
  }
}
