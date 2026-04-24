import type { TFile } from 'obsidian';
import type { NormalizedSbomDocument } from '../../domain/sbom/types';

export interface ParseSbomOptions {
  source: Pick<TFile, 'basename' | 'path'>;
  resolveNotePath?: (component: {
    cpe?: string;
    name: string;
    purl?: string;
    version?: string;
  }) => string | null | undefined;
}

export interface SbomParser {
  readonly format: NormalizedSbomDocument['format'];
  canParse(document: unknown): boolean;
  parse(document: unknown, options: ParseSbomOptions): NormalizedSbomDocument;
}

export const createUnsupportedSbomFormatError = (sourcePath: string): Error =>
  new Error(
    `Unsupported SBOM JSON format in "${sourcePath}". Supported formats: CycloneDX JSON and SPDX JSON.`
  );
