import assert from 'node:assert/strict';
import test from 'node:test';
import type { NormalizedSbomDocument } from '../../../src/domain/sbom/types';
import { SbomParserFactory } from '../../../src/infrastructure/parsers/SbomParserFactory';
import type { ParseSbomOptions, SbomParser } from '../../../src/infrastructure/parsers/SbomParser';

class FakeSbomParser implements SbomParser {
  public readonly format: NormalizedSbomDocument['format'];
  private readonly canParseResult: boolean;

  public constructor(
    format: NormalizedSbomDocument['format'],
    canParseResult: boolean
  ) {
    this.format = format;
    this.canParseResult = canParseResult;
  }

  public canParse(): boolean {
    return this.canParseResult;
  }

  public parse(_document: unknown, options: ParseSbomOptions): NormalizedSbomDocument {
    return {
      components: [],
      format: this.format,
      name: `${this.format}:${options.source.basename}`,
      sourcePath: options.source.path
    };
  }
}

const createSource = (path: string): ParseSbomOptions['source'] => ({
  basename: path.split('/').at(-1)?.replace(/\.json$/i, '') ?? path,
  path
});

test('SbomParserFactory prefers CycloneDX parser when the source path hints at CycloneDX', () => {
  const factory = new SbomParserFactory([
    new FakeSbomParser('spdx', true),
    new FakeSbomParser('cyclonedx', true)
  ]);

  const result = factory.parse({}, { source: createSource('reports/app.cdx.json') });

  assert.equal(result.format, 'cyclonedx');
});

test('SbomParserFactory falls back to content detection when no source hint is present', () => {
  const factory = new SbomParserFactory([
    new FakeSbomParser('spdx', false),
    new FakeSbomParser('cyclonedx', true)
  ]);

  const result = factory.parse({}, { source: createSource('reports/app.json') });

  assert.equal(result.format, 'cyclonedx');
});

test('SbomParserFactory fails safely for unsupported SBOM content', () => {
  const factory = new SbomParserFactory([
    new FakeSbomParser('cyclonedx', false),
    new FakeSbomParser('spdx', false)
  ]);

  assert.throws(
    () => factory.parse({}, { source: createSource('reports/notes.json') }),
    /Unsupported SBOM JSON format in "reports\/notes\.json"\. Supported formats: CycloneDX JSON and SPDX JSON\./
  );
});
