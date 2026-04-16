import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomImportService } from '../../../src/application/services/SbomImportService';
import type { ImportedSbomConfig } from '../../../src/application/services/types';

class InMemorySbomReader {
  private readonly files: Record<string, string>;

  public constructor(files: Record<string, string>) {
    this.files = files;
  }

  public async exists(path: string): Promise<boolean> {
    return Object.prototype.hasOwnProperty.call(this.files, path);
  }

  public async read(path: string): Promise<string> {
    const value = this.files[path];
    if (value === undefined) {
      throw new Error('ENOENT');
    }

    return value;
  }
}

class MutableSbomReader extends InMemorySbomReader {
  private readonly mutableFiles: Record<string, string>;

  public constructor(mutableFiles: Record<string, string>) {
    super(mutableFiles);
    this.mutableFiles = mutableFiles;
  }

  public delete(path: string): void {
    delete this.mutableFiles[path];
  }
}

const createSbomConfig = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: 'sbom-1',
  label: 'Primary SBOM',
  lastImportedAt: 0,
  path: 'reports/sbom.json',
  ...overrides
});

test('loads CycloneDX components into runtime cache, normalizes names, and deduplicates by original name', async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': JSON.stringify({
      bomFormat: 'CycloneDX',
      metadata: {
        component: {
          name: 'platform-api'
        }
      },
      components: [
        { name: 'platform-api' },
        { name: 'apache-tomcat-10.1.31' },
        { name: 'apache-tomcat-10.1.31' }
      ]
    })
  }));

  const result = await service.loadSbom(createSbomConfig());

  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }

  assert.equal(result.state.components.length, 2);
  assert.equal(result.state.document.format, 'cyclonedx');
  assert.equal(result.state.components[0]?.normalizedName, 'Apache Tomcat 10.1.31');
  assert.equal(result.state.components[1]?.normalizedName, 'Platform Api');
  assert.equal(typeof result.state.hash, 'string');
  assert.equal(service.getRuntimeState('sbom-1')?.components.length, 2);
});

test('loads SPDX package metadata through the shared parser', async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.spdx.json': JSON.stringify({
      SPDXID: 'SPDXRef-DOCUMENT',
      name: 'Primary SPDX Document',
      packages: [
        {
          SPDXID: 'SPDXRef-Package-portal-web',
          externalRefs: [
            {
              referenceLocator: 'pkg:npm/portal-web@1.2.3',
              referenceType: 'purl'
            }
          ],
          licenseDeclared: 'MIT',
          name: 'portal-web',
          supplier: 'Organization: Example Co',
          versionInfo: '1.2.3'
        }
      ],
      spdxVersion: 'SPDX-2.3'
    })
  }));

  const result = await service.loadSbom(createSbomConfig({
    path: 'reports/sbom.spdx.json'
  }));

  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }

  assert.equal(result.state.document.format, 'spdx');
  assert.equal(result.state.document.components[0]?.purl, 'pkg:npm/portal-web@1.2.3');
  assert.equal(result.state.components[0]?.normalizedName, 'Portal Web');
});

test('returns cached runtime data when a later forced load fails', async () => {
  const reader = new MutableSbomReader({
    'reports/sbom.json': JSON.stringify({ components: [{ name: 'portal-web' }] })
  });
  const service = new SbomImportService(reader);
  const config = createSbomConfig();

  const initialLoad = await service.loadSbom(config);
  assert.equal(initialLoad.success, true);

  reader.delete('reports/sbom.json');

  const failed = await service.loadSbom(config, { force: true });
  assert.equal(failed.success, false);
  assert.equal(failed.cachedState?.components[0]?.originalName, 'portal-web');
});

test('reports file hash status without mutating the runtime cache', async () => {
  const raw = JSON.stringify({ components: [{ name: 'widget' }] });
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': raw
  }));

  const loaded = await service.loadSbom(createSbomConfig());
  assert.equal(loaded.success, true);
  if (!loaded.success) {
    return;
  }

  const unchanged = await service.getFileChangeStatus(createSbomConfig({
    contentHash: loaded.state.hash
  }));
  assert.equal(unchanged.status, 'unchanged');

  const changedService = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': JSON.stringify({ components: [{ name: 'widget' }, { name: 'api-gateway' }] })
  }));
  const changed = await changedService.getFileChangeStatus(createSbomConfig({
    contentHash: loaded.state.hash
  }));
  assert.equal(changed.status, 'changed');
});

test('returns a safe failure for missing files', async () => {
  const service = new SbomImportService(new InMemorySbomReader({}));
  const result = await service.loadSbom(createSbomConfig());

  assert.equal(result.success, false);
  assert.equal(result.error, 'ENOENT');
  assert.equal(service.getRuntimeState('sbom-1'), null);
});

test('validates readable supported SBOM JSON files before they are attached', async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': JSON.stringify({
      bomFormat: 'CycloneDX',
      components: [{ name: 'portal-web' }, { name: 'api-gateway' }]
    })
  }));

  const result = await service.validateSbomPath('reports/sbom.json');
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }

  assert.equal(result.normalizedPath, 'reports/sbom.json');
  assert.equal(result.componentCount, 2);
});

test('validates SPDX JSON files before they are attached', async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.spdx.json': JSON.stringify({
      SPDXID: 'SPDXRef-DOCUMENT',
      packages: [
        { name: 'portal-web' },
        { name: 'api-gateway' }
      ],
      spdxVersion: 'SPDX-2.3'
    })
  }));

  const result = await service.validateSbomPath('reports/sbom.spdx.json');
  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }

  assert.equal(result.componentCount, 2);
});

test('rejects JSON files that are not a supported SBOM format', async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/notes.json': JSON.stringify({
      title: 'not an sbom'
    })
  }));

  const result = await service.validateSbomPath('reports/notes.json');
  assert.equal(result.success, false);
  assert.equal(
    result.error,
    'Unsupported SBOM JSON format in "reports/notes.json". Supported formats: CycloneDX JSON and SPDX JSON.'
  );
});
