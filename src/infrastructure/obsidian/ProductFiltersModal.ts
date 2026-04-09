import { App, Modal, Notice } from 'obsidian';
import type { VulnDashSettings } from '../../application/services/types';

export interface ProductFiltersSourceGroup {
  filters: string[];
  label: string;
  sbomId: string;
}

export interface ProductFiltersModalOptions {
  activeFilterCount: number;
  contributingSbomCount: number;
  enabledSbomCount: number;
  filters: string[];
  groups: ProductFiltersSourceGroup[];
  manualFilterCount: number;
  mode: VulnDashSettings['sbomImportMode'];
}

type ProductFilterSortMode = 'alphabetical' | 'source';

const BUTTON_FEEDBACK_MS = 1_200;

export class ProductFiltersModal extends Modal {
  private emptyStateEl: HTMLDivElement | null = null;
  private listEl: HTMLDivElement | null = null;
  private resultCountEl: HTMLParagraphElement | null = null;
  private searchQuery = '';
  private sortMode: ProductFilterSortMode = 'alphabetical';

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

    const stats = contentEl.createDiv({ cls: 'vulndash-product-filters-modal-stats' });
    this.createStatChip(stats, `${this.options.filters.length} SBOM-derived`);
    this.createStatChip(stats, `${this.options.manualFilterCount} manual`);
    this.createStatChip(stats, `${this.options.activeFilterCount} active total`, true);

    const stickyToolbar = contentEl.createDiv({ cls: 'vulndash-product-filters-sticky-toolbar' });
    const toolbarSummary = stickyToolbar.createDiv({ cls: 'vulndash-product-filters-modal-summary' });
    this.resultCountEl = toolbarSummary.createEl('p', { cls: 'vulndash-muted-copy' });
    const copyButton = toolbarSummary.createEl('button', { text: 'Copy All' });
    copyButton.disabled = this.options.filters.length === 0;
    copyButton.addEventListener('click', () => {
      if (this.options.filters.length === 0) {
        return;
      }

      void this.copyFilters(copyButton);
    });

    const controls = stickyToolbar.createDiv({ cls: 'vulndash-product-filters-toolbar-controls' });
    const searchInput = controls.createEl('input', {
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

    const sortField = controls.createDiv({ cls: 'vulndash-product-filters-sort' });
    sortField.createEl('label', { text: 'Sort' });
    const sortSelect = sortField.createEl('select');
    sortSelect.createEl('option', { text: 'Alphabetical', value: 'alphabetical' });
    sortSelect.createEl('option', { text: 'Source Grouping', value: 'source' });
    sortSelect.value = this.sortMode;
    sortSelect.addEventListener('change', () => {
      this.sortMode = sortSelect.value as ProductFilterSortMode;
      this.renderFilterList();
    });

    this.emptyStateEl = contentEl.createDiv({ cls: 'vulndash-empty-state vulndash-product-filters-empty-state is-compact' });
    const scrollContainer = contentEl.createDiv({ cls: 'vulndash-product-filters-scroll' });
    this.listEl = scrollContainer.createDiv({ cls: 'vulndash-product-filters-results' });
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
    if (this.options.filters.length === 0) {
      this.renderEmptyState(
        'No computed filters',
        'Computed filters will appear here after enabled SBOMs contribute derived product names.'
      );
      this.resultCountEl.textContent = this.getResultCountText(0, 0);
      return;
    }

    if (this.sortMode === 'source') {
      this.renderSourceGroupedList();
      return;
    }

    const filteredFilters = this.getFilteredAlphabeticalFilters();
    this.resultCountEl.textContent = this.getResultCountText(filteredFilters.length, this.options.filters.length);
    if (filteredFilters.length === 0) {
      this.renderEmptyState('No matching filters', 'Try a broader search or clear the current filter.');
      return;
    }

    this.emptyStateEl.empty();
    this.emptyStateEl.style.display = 'none';
    this.listEl.style.display = '';

    const chipGrid = this.listEl.createDiv({ cls: 'vulndash-product-filters-chip-grid' });
    for (const filter of filteredFilters) {
      chipGrid.createSpan({ cls: 'vulndash-product-filters-chip', text: filter });
    }
  }

  private renderSourceGroupedList(): void {
    if (!this.listEl || !this.emptyStateEl || !this.resultCountEl) {
      return;
    }

    const filteredGroups = this.getFilteredSourceGroups();
    const matchedFilterCount = filteredGroups.reduce((sum, group) => sum + group.filters.length, 0);
    const totalGroupedFilterCount = this.options.groups.reduce((sum, group) => sum + group.filters.length, 0);
    this.resultCountEl.textContent = `${matchedFilterCount} of ${totalGroupedFilterCount} source-grouped filter${totalGroupedFilterCount === 1 ? '' : 's'} shown across ${filteredGroups.length} source${filteredGroups.length === 1 ? '' : 's'}.`;

    if (matchedFilterCount === 0) {
      this.renderEmptyState('No matching filters', 'Try a broader search or switch back to alphabetical view.');
      return;
    }

    this.emptyStateEl.empty();
    this.emptyStateEl.style.display = 'none';
    this.listEl.style.display = '';

    const sourceList = this.listEl.createDiv({ cls: 'vulndash-product-filters-source-list' });
    for (const group of filteredGroups) {
      const section = sourceList.createDiv({ cls: 'vulndash-product-filters-source-group' });
      const header = section.createDiv({ cls: 'vulndash-product-filters-source-header' });
      header.createEl('h3', { cls: 'vulndash-product-filters-source-title', text: group.label });
      header.createSpan({
        cls: 'vulndash-product-filters-chip vulndash-product-filters-chip-muted',
        text: `${group.filters.length} filter${group.filters.length === 1 ? '' : 's'}`
      });

      const chipGrid = section.createDiv({ cls: 'vulndash-product-filters-chip-grid' });
      for (const filter of group.filters) {
        chipGrid.createSpan({ cls: 'vulndash-product-filters-chip', text: filter });
      }
    }
  }

  private getFilteredAlphabeticalFilters(): string[] {
    const normalizedQuery = this.searchQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return this.options.filters;
    }

    return this.options.filters.filter((filter) => filter.toLowerCase().includes(normalizedQuery));
  }

  private getFilteredSourceGroups(): ProductFiltersSourceGroup[] {
    const normalizedQuery = this.searchQuery.trim().toLowerCase();
    if (!normalizedQuery) {
      return this.options.groups;
    }

    return this.options.groups
      .map((group) => ({
        ...group,
        filters: group.filters.filter((filter) => filter.toLowerCase().includes(normalizedQuery))
      }))
      .filter((group) => group.filters.length > 0);
  }

  private renderEmptyState(title: string, body: string): void {
    if (!this.emptyStateEl || !this.listEl) {
      return;
    }

    this.emptyStateEl.empty();
    this.emptyStateEl.createEl('h3', { text: title });
    this.emptyStateEl.createEl('p', { text: body });
    this.emptyStateEl.style.display = '';
    this.listEl.style.display = 'none';
  }

  private getResultCountText(visibleCount: number, totalCount: number): string {
    return totalCount === 0
      ? '0 filters available.'
      : `${visibleCount} of ${totalCount} SBOM-derived filter${totalCount === 1 ? '' : 's'} shown.`;
  }

  private getSummaryText(): string {
    const derivedCount = this.options.filters.length;
    const manualCount = this.options.manualFilterCount;

    if (derivedCount === 0) {
      if (this.options.enabledSbomCount === 0) {
        return 'No computed filters are active. Enable an SBOM to derive filters automatically.';
      }

      if (this.options.mode === 'append' && manualCount > 0) {
        return `${manualCount} manual filter${manualCount === 1 ? '' : 's'} remain active in append mode, but no SBOM-derived filters are currently available.`;
      }

      return `No computed filters are active. Derived filters are computed from enabled SBOMs in ${this.options.mode} mode.`;
    }

    const sbomContext = this.options.contributingSbomCount === this.options.enabledSbomCount
      ? `${this.options.enabledSbomCount} enabled SBOM${this.options.enabledSbomCount === 1 ? '' : 's'}`
      : `${this.options.contributingSbomCount} of ${this.options.enabledSbomCount} enabled SBOMs`;

    if (this.options.mode === 'append') {
      return `${derivedCount} SBOM-derived filter${derivedCount === 1 ? '' : 's'} shown. ${manualCount} manual filter${manualCount === 1 ? '' : 's'} also remain active in append mode, for ${this.options.activeFilterCount} total active filters. Computed from ${sbomContext}.`;
    }

    if (manualCount > 0) {
      return `${derivedCount} SBOM-derived filter${derivedCount === 1 ? '' : 's'} shown. ${manualCount} manual filter${manualCount === 1 ? '' : 's'} are configured, but replace mode uses SBOM-derived filters only. Computed from ${sbomContext}.`;
    }

    return `${derivedCount} SBOM-derived filter${derivedCount === 1 ? '' : 's'} shown. Computed from ${sbomContext} in replace mode.`;
  }

  private createStatChip(containerEl: HTMLElement, label: string, muted = false): void {
    containerEl.createSpan({
      cls: `vulndash-product-filters-chip${muted ? ' vulndash-product-filters-chip-muted' : ''}`,
      text: label
    });
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
