import { App, FuzzySuggestModal, type FuzzyMatch } from 'obsidian';
import type { ProjectNoteOption } from '../../infrastructure/obsidian/ProjectNoteLookupService';

const compareProjectNotes = (left: ProjectNoteOption, right: ProjectNoteOption): number =>
  left.displayName.localeCompare(right.displayName)
  || left.notePath.localeCompare(right.notePath);

export class ProjectNoteSuggestModal extends FuzzySuggestModal<ProjectNoteOption> {
  private readonly notes: ProjectNoteOption[];

  public constructor(
    app: App,
    notes: readonly ProjectNoteOption[],
    private readonly onChoose: (note: ProjectNoteOption) => void
  ) {
    super(app);
    this.notes = [...notes].sort(compareProjectNotes);
    this.setPlaceholder('Select a project note');
  }

  public override getItems(): ProjectNoteOption[] {
    return this.notes;
  }

  public override getItemText(note: ProjectNoteOption): string {
    return `${note.displayName} ${note.notePath}`;
  }

  public override renderSuggestion(match: FuzzyMatch<ProjectNoteOption>, el: HTMLElement): void {
    el.empty();

    const note = match.item;
    const row = el.createDiv({ cls: 'vulndash-sbom-file-suggestion' });
    row.createDiv({ cls: 'vulndash-sbom-file-suggestion-title', text: note.displayName });
    row.createDiv({ cls: 'vulndash-sbom-file-suggestion-path', text: note.notePath });
  }

  public override onChooseItem(note: ProjectNoteOption): void {
    this.onChoose(note);
  }
}
