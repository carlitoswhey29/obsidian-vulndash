import { App, FuzzySuggestModal, type FuzzyMatch, TFile } from 'obsidian';
import { sortSbomFileCandidates } from '../../application/use-cases/SbomWorkspaceService';

export class SbomFileSuggestModal extends FuzzySuggestModal<TFile> {
  private readonly files: TFile[];

  public constructor(
    app: App,
    private readonly onChoose: (file: TFile) => void
  ) {
    super(app);
    this.files = sortSbomFileCandidates(this.app.vault.getFiles());
    this.setPlaceholder('Select an SBOM JSON file');
  }

  public override getItems(): TFile[] {
    return this.files;
  }

  public override getItemText(file: TFile): string {
    return file.path;
  }

  public override renderSuggestion(match: FuzzyMatch<TFile>, el: HTMLElement): void {
    el.empty();

    const file = match.item;
    const row = el.createDiv({ cls: 'vulndash-sbom-file-suggestion' });
    row.createDiv({ cls: 'vulndash-sbom-file-suggestion-title', text: file.basename });
    row.createDiv({ cls: 'vulndash-sbom-file-suggestion-path', text: file.path });
  }

  public override onChooseItem(file: TFile): void {
    this.onChoose(file);
  }
}
