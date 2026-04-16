import type { TFile } from 'obsidian';
import type { NormalizedSbomDocument } from '../types';
import { isCycloneDxJson, parseCycloneDxJson } from './cyclonedx';
import { isSpdxJson, parseSpdxJson } from './spdx';

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
