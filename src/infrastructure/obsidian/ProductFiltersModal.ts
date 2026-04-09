import { App, Modal, Notice } from 'obsidian';
import type { VulnDashSettings } from '../../application/services/types';

export interface ProductFiltersModalOptions {
  contributingSbomCount: number;
  enabledSbomCount: number;
  filters: string[];
  mode: VulnDashSettings['sbomImportMode'];
}

const BUTTON_FEEDBACK_MS = 1_200;

export class ProductFiltersModal extends Modal {
  private emptyStateEl: HTMLDivElement | null = null;
  private listEl: HTMLDivElement | null = null;
  private resultCountEl: HTMLParagraphElement | null = null;
  private searchQuery = '';

  public constructor(
    app: App,
    private readonly options: ProductFiltersModalOptions
  ) {
    super(app);
  }

  public override onOpen(): void {
    this.modalEl.addClass('vulndash-product-filters-modal');
    this.render();
  }

  private render(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.emptyStateEl = null;
    this.listEl = null;
    this.resultCountEl = null;

    const header = contentEl.createDiv({ cls: 'vulndash-modal-header' });
    header.createEl('h2', { text: 'Computed Product Filters' });
    header.createEl('p', {
      cls: 'vulndash-muted-copy',
      text: this.getSummaryText()
    });

    const summary = contentEl.createDiv({ cls: 'vulndash-product-filters-modal-summary' });
    this.resultCountEl = summary.createEl('p', { cls: 'vulndash-muted-copy' });
    const copyButton = summary.createEl('button', { text: 'Copy All' });
    copyButton.disabled = this.options.filters.length === 0;
    copyButton.addEventListener('click', () => {
      if (this.options.filters.length === 0) {
        return;
      }

      void this.copyFilters(copyButton);
    });

    const searchInput = contentEl.createEl('input', {
      cls: 'vulndash-product-filters-search',
      attr: {
        placeholder: 'Search computed filters',
        type: 'search'
      }
    });
    searchInput.value = this.searchQuery;
    searchInput.addEventListener('input', () => {
      this.searchQuery = searchInput.value;
      this.renderFilterList();
    });

    this.emptyStateEl = contentEl.createDiv({ cls: 'vulndash-empty-state vulndash-product-filters-empty-state is-compact' });
    const scrollContainer = contentEl.createDiv({ cls: 'vulndash-product-filters-scroll' });
    this.listEl = scrollContainer.createDiv({ cls: 'vulndash-product-filters-chip-grid' });
    this.renderFilterList();

    window.setTimeout(() => {
      if (searchInput.isConnected) {
        searchInput.focus();
      }
    }, 0);
  }

  private renderFilterList(): void {
    if (!this.listEl || !this.emptyStateEl || !this.resultCountEl) {
      return;
    }

    this.listEl.empty();
    const filteredFilters = this.getFilteredFilters();
    const totalFilters = this.options.filters.length;
    this.resultCountEl.textContent = totalFilters === 0
      ? '0 filters available.'
      : `${filteredFilters.length} of ${totalFilters} filter${totalFilters === 1 ? '' : 's'} shown.`;

    if (filteredFilters.length === 0) {
      this.emptyStateEl.empty();
      this.emptyStateEl.createEl('h3', {
        text: totalFilters === 0 ? 'No computed filters' : 'No matching filters'
      });
      this.emptyStateEl.createEl('p', {
        text: totalFilters === 0
          ? 'Computed filters will appear here after enabled SBOMs contribute derived product names.'
          : 'Try a broader search or clear the current filter.'
      });
      this.emptyStateEl.style.display = '';
      this.listEl.style.display = 'none';
      return;
    }

    this.emptyStateEl.empty();
    this.emptyStateEl.style.display = 'none';
    this.listEl.style.display = '';

    for (const filter of filteredFilters) {
      this.listEl.createSpan({ cls: 'vulndash-product-filters-chip', text: filter });
    }
  }

  private getFilteredFilters(): string[] {
    const normalizedQuery = this.searchQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return this.options.filters;
    }

    return this.options.filters.filter((filter) => filter.toLowerCase().includes(normalizedQuery));
  }

  private getSummaryText(): string {
    if (this.options.filters.length === 0) {
      if (this.options.enabledSbomCount === 0) {
        return 'No computed filters are active. Enable an SBOM to derive filters automatically.';
      }

      return `No computed filters are active. Derived filters are computed from enabled SBOMs in ${this.options.mode} mode.`;
    }

    const sbomContext = this.options.contributingSbomCount === this.options.enabledSbomCount
      ? `${this.options.enabledSbomCount} enabled SBOM${this.options.enabledSbomCount === 1 ? '' : 's'}`
      : `${this.options.contributingSbomCount} of ${this.options.enabledSbomCount} enabled SBOMs`;

    return `${this.options.filters.length} computed filter${this.options.filters.length === 1 ? '' : 's'} active. Computed from ${sbomContext} in ${this.options.mode} mode.`;
  }

  private async copyFilters(buttonEl: HTMLButtonElement): Promise<void> {
    const buttonWasDisabled = buttonEl.disabled;
    buttonEl.disabled = true;

    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('Clipboard API unavailable');
      }

      await navigator.clipboard.writeText(this.options.filters.join('\n'));
      buttonEl.textContent = 'Copied';
      window.setTimeout(() => {
        if (!buttonEl.isConnected) {
          return;
        }

        buttonEl.textContent = 'Copy All';
        buttonEl.disabled = buttonWasDisabled;
      }, BUTTON_FEEDBACK_MS);
    } catch {
      buttonEl.textContent = 'Copy All';
      buttonEl.disabled = buttonWasDisabled;
      new Notice('Unable to copy computed filters.');
    }
  }
}
