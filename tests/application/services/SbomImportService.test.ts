import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomImportService } from '../../../src/application/services/SbomImportService';
import type { ImportedSbomConfig } from '../../../src/application/services/types';

class InMemorySbomReader {
  public constructor(private readonly files: Record<string, string>) {}

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

const createSbomConfig = (overrides: Partial<ImportedSbomConfig> = {}): ImportedSbomConfig => ({
  id: 'sbom-1',
  label: 'Primary SBOM',
  path: 'reports/sbom.json',
  namespace: '',
  enabled: true,
  components: [],
  lastImportedAt: null,
  lastImportHash: null,
  lastImportError: null,
  ...overrides
});

test('imports CycloneDX components, normalizes names, and preserves existing exclude flags by identity', async () => {
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': JSON.stringify({
      metadata: {
        component: {
          name: 'platform-api',
          version: '1.0.0',
          purl: 'pkg:npm/%40acme/platform-api@1.0.0'
        }
      },
      components: [
        {
          name: 'platform-api',
          version: '1.0.0',
          purl: 'pkg:npm/%40acme/platform-api@1.0.0'
        },
        {
          cpe: 'cpe:2.3:a:apache:tomcat:10.1.31:*:*:*:*:*:*:*'
        }
      ]
    })
  }));

  const result = await service.importSbom(createSbomConfig({
    components: [{
      id: 'component-1',
      name: 'platform-api',
      normalizedName: 'Platform Api',
      version: '1.0.0',
      purl: 'pkg:npm/%40acme/platform-api@1.0.0',
      cpe: '',
      bomRef: '',
      namespace: '@acme',
      enabled: true,
      excluded: true
    }]
  }));

  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }

  assert.equal(result.importedComponentCount, 2);
  assert.equal(result.sbom.components.length, 2);
  assert.equal(result.sbom.components[0]?.normalizedName, 'Apache Tomcat 10.1.31');
  assert.equal(result.sbom.components[1]?.normalizedName, 'Platform Api');
  assert.equal(result.sbom.components[1]?.excluded, true);
  assert.equal(result.sbom.components[1]?.namespace, '@acme');
  assert.equal(typeof result.sbom.lastImportHash, 'string');
  assert.equal(result.sbom.lastImportError, null);
});

test('returns failure for invalid JSON and does not mutate the existing stored config', async () => {
  const existing = createSbomConfig({
    components: [{
      id: 'component-1',
      name: 'Existing Component',
      normalizedName: 'Existing Component',
      version: '1.2.3',
      purl: '',
      cpe: '',
      bomRef: '',
      namespace: '',
      enabled: true,
      excluded: false
    }]
  });

  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': '{invalid-json'
  }));

  const result = await service.importSbom(existing);
  assert.equal(result.success, false);
  assert.equal(existing.components.length, 1);
  assert.equal(existing.components[0]?.name, 'Existing Component');
});

test('reports file hash status without mutating stored components', async () => {
  const raw = JSON.stringify({ components: [{ name: 'widget' }] });
  const service = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': raw
  }));

  const imported = await service.importSbom(createSbomConfig());
  assert.equal(imported.success, true);
  if (!imported.success) {
    return;
  }

  const unchanged = await service.getFileChangeStatus(imported.sbom);
  assert.equal(unchanged.status, 'unchanged');

  const changedService = new SbomImportService(new InMemorySbomReader({
    'reports/sbom.json': JSON.stringify({ components: [{ name: 'widget' }, { name: 'api-gateway' }] })
  }));
  const changed = await changedService.getFileChangeStatus(imported.sbom);
  assert.equal(changed.status, 'changed');
});
