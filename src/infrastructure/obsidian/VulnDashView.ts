import { ItemView, WorkspaceLeaf } from 'obsidian';
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

  private render(): void {
    const { contentEl } = this;
    contentEl.empty();

    const header = contentEl.createDiv({ cls: 'vulndash-header' });
    header.createEl('h2', { text: 'VulnDash Dashboard' });
    const refreshBtn = header.createEl('button', { text: 'Refresh now' });
    refreshBtn.addEventListener('click', () => {
      void this.onRefresh();
    });

    const table = contentEl.createEl('table', { cls: 'vulndash-table' });
    const thead = table.createEl('thead');
    const headRow = thead.createEl('tr');

    const columns: Array<{ key: SortKey; label: string }> = [
      { key: 'id', label: 'ID' },
      { key: 'source', label: 'Source' },
      { key: 'severity', label: 'Severity' },
      { key: 'cvssScore', label: 'CVSS' },
      { key: 'publishedAt', label: 'Published' }
    ];

    for (const column of columns) {
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
    for (const vuln of this.getSorted()) {
      const row = tbody.createEl('tr');
      const idCell = row.createEl('td', { text: sanitizeText(vuln.id) });
      if (this.newItems.has(vuln.id)) {
        idCell.addClass('vulndash-new');
      }

      row.createEl('td', { text: sanitizeText(vuln.source) });
      const sev = row.createEl('td', { text: sanitizeText(vuln.severity) });
      if (vuln.severity === 'CRITICAL') {
        sev.addClass('vulndash-critical');
      }

      row.createEl('td', { text: vuln.cvssScore.toFixed(1) });
      row.createEl('td', { text: new Date(vuln.publishedAt).toLocaleString() });

      const details = tbody.createEl('tr');
      const detailsCell = details.createEl('td', { attr: { colspan: '5' } });
      detailsCell.createEl('strong', { text: sanitizeText(vuln.title) });
      detailsCell.createEl('p', { text: sanitizeText(vuln.summary) });
      const refs = detailsCell.createDiv();
      for (const ref of vuln.references.slice(0, 3)) {
        const a = refs.createEl('a', { text: ref });
        a.href = ref;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        refs.createEl('br');
      }
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
