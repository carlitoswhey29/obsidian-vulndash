import type { CachedMetadata, MetadataCache, TFile, Vault } from 'obsidian';
import { normalizePath } from 'obsidian';
import {
  ComponentNotePathResolver,
  type ComponentNoteCandidate
} from '../../application/sbom/ComponentStorageResolver';

interface MarkdownWorkspace {
  getMarkdownFiles(): TFile[];
}

interface FrontmatterWorkspace {
  getFileCache(file: TFile): CachedMetadata | null;
}

const getFrontmatter = (
  metadataCache: FrontmatterWorkspace,
  file: TFile
): Record<string, unknown> | undefined => {
  const frontmatter = metadataCache.getFileCache(file)?.frontmatter;
  if (!frontmatter || typeof frontmatter !== 'object') {
    return undefined;
  }

  return frontmatter as Record<string, unknown>;
};

export class ComponentNoteResolverFactory {
  public constructor(
    private readonly vault: Pick<Vault, 'getMarkdownFiles'> & MarkdownWorkspace,
    private readonly metadataCache: Pick<MetadataCache, 'getFileCache'> & FrontmatterWorkspace
  ) {}

  public createResolver(): ComponentNotePathResolver {
    const candidates: ComponentNoteCandidate[] = this.vault.getMarkdownFiles().map((file) => {
      const candidate: ComponentNoteCandidate = {
        basename: file.basename,
        path: normalizePath(file.path)
      };
      const frontmatter = getFrontmatter(this.metadataCache, file);
      if (frontmatter) {
        candidate.frontmatter = frontmatter;
      }

      return candidate;
    });

    return new ComponentNotePathResolver(candidates);
  }
}
