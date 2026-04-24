import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizePath, TFile } from 'obsidian';
import { VulnDashAppModule } from '../../src/application/VulnDashAppModule';

const createMarkdownFile = (path: string): TFile => Object.assign(new TFile(), {
  basename: path.split('/').at(-1)?.replace(/\.md$/i, '') ?? path,
  path: normalizePath(path)
});

test('VulnDashAppModule exposes explicit note lookup and cache invalidation entrypoints', async () => {
  const projectFile = createMarkdownFile('projects/portal-web.md');
  const vault = {
    adapter: {
      exists: async () => true,
      read: async () => '',
      write: async () => undefined
    },
    create: async () => ({}),
    createFolder: async () => ({}),
    getAbstractFileByPath: (path: string) => normalizePath(path) === projectFile.path ? projectFile : null,
    getMarkdownFiles: () => [projectFile]
  };
  const module = VulnDashAppModule.create({
    getActiveWorkspacePurls: async () => [],
    getSboms: () => [],
    metadataCache: {
      getFileCache: () => null
    },
    normalizePath,
    updateSbomConfig: async () => undefined,
    vault
  });

  assert.deepEqual(module.listProjectNotes(), [{
    displayName: 'portal-web',
    notePath: 'projects/portal-web.md'
  }]);

  const linked = await module.resolveProjectNotePath('projects/portal-web.md');
  assert.equal(linked.status, 'linked');
  assert.equal(linked.displayName, 'portal-web');

  let invalidateAllCachesCalls = 0;
  let invalidatedSbomId: string | null = null;
  const importService = module.sbomImportService as {
    invalidateAllCaches(): void;
    invalidateCache(sbomId: string): void;
  };
  importService.invalidateAllCaches = () => {
    invalidateAllCachesCalls += 1;
  };
  importService.invalidateCache = (sbomId: string) => {
    invalidatedSbomId = sbomId;
  };

  module.invalidateMarkdownNotePathCaches();
  module.invalidateSbomCache('sbom-1');

  assert.equal(invalidateAllCachesCalls, 1);
  assert.equal(invalidatedSbomId, 'sbom-1');
});
