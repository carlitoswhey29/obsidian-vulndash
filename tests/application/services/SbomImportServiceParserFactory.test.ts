import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomImportService } from '../../../src/application/use-cases/SbomImportService';
import type { ImportedSbomConfig } from '../../../src/application/use-cases/types';
import type { NormalizedSbomDocument } from '../../../src/domain/sbom/types';

class InMemorySbomReader {
  public constructor(
    private readonly files: Record<string, string>
  ) {}

  public async exists(path: string): Promise<boolean> {
    return this.files[path] !== undefined;
  }

  public async read(path: string): Promise<string> {
    const value = this.files[path];
    if (value === undefined) {
      throw new Error('ENOENT');
    }

    return value;
  }
}

const createSbomConfig = (): ImportedSbomConfig => ({
  contentHash: '',
  enabled: true,
  id: 'sbom-1',
  label: 'Primary SBOM',
  lastImportedAt: 0,
  path: 'reports/application.spdx.json'
});

test('SbomImportService parses through the configured parser factory', async () => {
  const observedSources: NormalizedSbomDocument['sourcePath'][] = [];
  const parserFactory = {
    parse(_document: unknown, options: { source: { basename: string; path: string } }): NormalizedSbomDocument {
      observedSources.push(options.source.path);

      return {
        components: [{
          cweGroups: [],
          id: 'pkg:demo/component@1.0.0',
          name: 'Demo Component',
          vulnerabilitySummary: {
            cweIds: [],
            severities: [],
            vulnerabilityCount: 0,
            vulnerabilityIds: []
          },
          vulnerabilities: [],
          vulnerabilityCount: 0
        }],
        format: 'spdx',
        name: options.source.basename,
        sourcePath: options.source.path
      };
    }
  };
  const service = new SbomImportService(
    new InMemorySbomReader({
      'reports/application.spdx.json': '{"SPDXID":"SPDXRef-DOCUMENT"}'
    }),
    undefined,
    null,
    { parserFactory }
  );

  const result = await service.loadSbom(createSbomConfig());

  assert.equal(result.success, true);
  if (!result.success) {
    return;
  }

  assert.deepEqual(observedSources, ['reports/application.spdx.json']);
  assert.equal(result.state.document.format, 'spdx');
  assert.equal(result.state.document.name, 'application.spdx');
  assert.equal(result.state.components[0]?.originalName, 'Demo Component');
});
