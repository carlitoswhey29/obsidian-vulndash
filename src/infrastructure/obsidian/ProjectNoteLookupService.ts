import { TFile, normalizePath } from 'obsidian';
import type {
  ProjectNoteLookup,
  ProjectNoteLookupResult
} from '../../application/correlation/ResolveAffectedProjects';
import type { ProjectNoteReference } from '../../domain/correlation/ProjectNoteReference';

export interface ProjectNoteOption {
  readonly displayName: string;
  readonly notePath: string;
}

interface VaultLike {
  getAbstractFileByPath(path: string): unknown;
  getMarkdownFiles(): TFile[];
}

const compareProjectNoteOptions = (left: ProjectNoteOption, right: ProjectNoteOption): number =>
  left.displayName.localeCompare(right.displayName)
  || left.notePath.localeCompare(right.notePath);

const getFallbackDisplayName = (
  notePath: string,
  displayName?: string
): string => {
  const normalizedDisplayName = displayName?.trim();
  if (normalizedDisplayName) {
    return normalizedDisplayName;
  }

  const segments = normalizePath(notePath).split('/').filter(Boolean);
  const filename = segments.at(-1) ?? notePath;
  return filename.replace(/\.md$/i, '') || notePath;
};

export class ProjectNoteLookupService implements ProjectNoteLookup {
  public constructor(
    private readonly vault: VaultLike
  ) {}

  public async getByPaths(references: readonly ProjectNoteReference[]): Promise<Map<string, ProjectNoteLookupResult>> {
    const resolved = new Map<string, ProjectNoteLookupResult>();

    for (const reference of references) {
      const noteState = await this.resolveByPath(reference.notePath, reference.displayName);
      resolved.set(noteState.notePath, noteState);
    }

    return resolved;
  }

  public listProjectNotes(): ProjectNoteOption[] {
    return this.vault.getMarkdownFiles()
      .map((file) => ({
        displayName: file.basename,
        notePath: normalizePath(file.path)
      }))
      .sort(compareProjectNoteOptions);
  }

  public async resolveByPath(notePath: string, displayName?: string): Promise<ProjectNoteLookupResult> {
    const normalizedPath = normalizePath(notePath.trim());
    const target = this.vault.getAbstractFileByPath(normalizedPath);

    if (target instanceof TFile) {
      return {
        displayName: target.basename,
        notePath: normalizePath(target.path),
        status: 'linked'
      };
    }

    return {
      displayName: getFallbackDisplayName(normalizedPath, displayName),
      notePath: normalizedPath,
      status: 'broken'
    };
  }
}
