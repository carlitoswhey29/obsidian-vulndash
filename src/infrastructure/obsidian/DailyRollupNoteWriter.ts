import type { RenderedDailyRollup } from '../../application/rollup/RollupMarkdownRenderer';
import { MarkdownSectionMerger } from './MarkdownSectionMerger';

export interface DailyRollupVaultAdapter {
  create(path: string, content: string): Promise<void>;
  createFolder(path: string): Promise<void>;
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
  write(path: string, content: string): Promise<void>;
}

const normalizePath = (value: string): string =>
  value
    .trim()
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^\.?\//, '');

export class DailyRollupNoteWriter {
  public constructor(
    private readonly vault: DailyRollupVaultAdapter,
    private readonly merger = new MarkdownSectionMerger()
  ) {}

  public async write(input: {
    readonly date: string;
    readonly document: RenderedDailyRollup;
    readonly folderPath: string;
  }): Promise<{
    readonly content: string;
    readonly created: boolean;
    readonly path: string;
  }> {
    const folderPath = normalizePath(input.folderPath);
    const notePath = folderPath.length > 0
      ? `${folderPath}/VulnDash Briefing ${input.date}.md`
      : `VulnDash Briefing ${input.date}.md`;
    await this.ensureFolder(folderPath);

    const exists = await this.vault.exists(notePath);
    const existingContent = exists ? await this.vault.read(notePath) : null;
    const content = this.merger.merge({
      analystNotesHeading: input.document.analystNotesHeading,
      analystNotesPlaceholder: input.document.analystNotesPlaceholder,
      existingContent,
      managedSections: input.document.managedSections,
      title: input.document.title
    });

    if (!exists) {
      await this.vault.create(notePath, content);
      return {
        content,
        created: true,
        path: notePath
      };
    }

    if (existingContent !== content) {
      await this.vault.write(notePath, content);
    }

    return {
      content,
      created: false,
      path: notePath
    };
  }

  private async ensureFolder(folderPath: string): Promise<void> {
    if (!folderPath || folderPath === '/') {
      return;
    }

    if (await this.vault.exists(folderPath)) {
      return;
    }

    const parts = folderPath.split('/').filter(Boolean);
    let current = '';
    for (const part of parts) {
      current = current ? `${current}/${part}` : part;
      if (!await this.vault.exists(current)) {
        await this.vault.createFolder(current);
      }
    }
  }
}
