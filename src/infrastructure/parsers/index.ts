import type { TFile } from 'obsidian';
import type { NormalizedSbomDocument } from '../../domain/sbom/types';
import { isCycloneDxJson, parseCycloneDxJson } from './CycloneDxParser';
import { isSpdxJson, parseSpdxJson } from './SpdxParser';

export interface ParseSbomJsonOptions {
  source: Pick<TFile, 'basename' | 'path'>;
  resolveNotePath?: (component: {
    cpe?: string;
    name: string;
    purl?: string;
    version?: string;
  }) => string | null | undefined;
}

export const parseSbomJson = (
  json: unknown,
  options: ParseSbomJsonOptions
): NormalizedSbomDocument => {
  if (isCycloneDxJson(json)) {
    return parseCycloneDxJson(json, options);
  }

  if (isSpdxJson(json)) {
    return parseSpdxJson(json, options);
  }

  throw new Error(
    `Unsupported SBOM JSON format in "${options.source.path}". Supported formats: CycloneDX JSON and SPDX JSON.`
  );
};
