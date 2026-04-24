import type { NormalizedSbomDocument } from '../../domain/sbom/types';
import { cycloneDxParser } from './CycloneDxParser';
import type { ParseSbomOptions, SbomParser } from './SbomParser';
import { createUnsupportedSbomFormatError } from './SbomParser';
import { spdxParser } from './SpdxParser';

const normalizeSourcePath = (path: string): string => path.replace(/\\/g, '/').toLowerCase();

const getPreferredFormats = (sourcePath: string): readonly NormalizedSbomDocument['format'][] => {
  const normalized = normalizeSourcePath(sourcePath);

  if (normalized.endsWith('.cdx.json') || normalized.endsWith('.cyclonedx.json') || normalized.includes('cyclonedx')) {
    return ['cyclonedx'];
  }

  if (normalized.endsWith('.spdx.json') || normalized.includes('spdx')) {
    return ['spdx'];
  }

  return [];
};

export class SbomParserFactory {
  public constructor(
    private readonly parsers: readonly SbomParser[] = [cycloneDxParser, spdxParser]
  ) {}

  public create(document: unknown, options: ParseSbomOptions): SbomParser {
    const preferredFormats = getPreferredFormats(options.source.path);
    const preferredParsers = preferredFormats.flatMap((format) =>
      this.parsers.filter((parser) => parser.format === format));
    const fallbackParsers = this.parsers.filter((parser) => !preferredParsers.includes(parser));

    for (const parser of [...preferredParsers, ...fallbackParsers]) {
      if (parser.canParse(document)) {
        return parser;
      }
    }

    throw createUnsupportedSbomFormatError(options.source.path);
  }

  public parse(document: unknown, options: ParseSbomOptions) {
    return this.create(document, options).parse(document, options);
  }
}
