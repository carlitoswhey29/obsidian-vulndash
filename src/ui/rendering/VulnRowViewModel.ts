import type { RelatedComponentSummary } from '../../application/sbom/types';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import { sanitizeMarkdown, sanitizeText, sanitizeUrl } from '../../infrastructure/utils/sanitize';

export type VulnerabilityRowColumnKey = 'cvssScore' | 'id' | 'publishedAt' | 'severity' | 'source' | 'title';

export interface VulnerabilityRowColumn {
  key: VulnerabilityRowColumnKey;
  label: string;
}

export interface RelatedComponentBadgeViewModel {
  evidence: string;
  label: string;
}

export interface VulnRowViewModel {
  columnKeys: readonly VulnerabilityRowColumnKey[];
  cvssText: string;
  expanded: boolean;
  idText: string;
  isNew: boolean;
  key: string;
  publishedAtText: string;
  referenceUrls: readonly string[];
  relatedComponents: readonly RelatedComponentBadgeViewModel[];
  severityClassName: string;
  severityText: string;
  sourceText: string;
  summaryMarkdown: string;
  titleText: string;
}

const areStringArraysEqual = (left: readonly string[], right: readonly string[]): boolean =>
  left.length === right.length && left.every((value, index) => value === right[index]);

export const areRelatedComponentsEqual = (
  left: readonly RelatedComponentBadgeViewModel[],
  right: readonly RelatedComponentBadgeViewModel[]
): boolean =>
  left.length === right.length
  && left.every((value, index) => value.label === right[index]?.label && value.evidence === right[index]?.evidence);

export const areVulnRowViewModelsEqual = (left: VulnRowViewModel, right: VulnRowViewModel): boolean =>
  areStringArraysEqual(left.columnKeys, right.columnKeys)
  && left.cvssText === right.cvssText
  && left.expanded === right.expanded
  && left.idText === right.idText
  && left.isNew === right.isNew
  && left.key === right.key
  && left.publishedAtText === right.publishedAtText
  && areStringArraysEqual(left.referenceUrls, right.referenceUrls)
  && areRelatedComponentsEqual(left.relatedComponents, right.relatedComponents)
  && left.severityClassName === right.severityClassName
  && left.severityText === right.severityText
  && left.sourceText === right.sourceText
  && left.summaryMarkdown === right.summaryMarkdown
  && left.titleText === right.titleText;

export const buildVulnRowViewModel = (
  vulnerability: Vulnerability,
  options: {
    colorCodedSeverity: boolean;
    columns: readonly VulnerabilityRowColumn[];
    expanded: boolean;
    getRowKey: (vulnerability: Vulnerability) => string;
    isNew: boolean;
    relatedComponents: readonly RelatedComponentSummary[];
  }
): VulnRowViewModel => ({
  columnKeys: options.columns.map((column) => column.key),
  cvssText: vulnerability.cvssScore.toFixed(1),
  expanded: options.expanded,
  idText: sanitizeText(vulnerability.id),
  isNew: options.isNew,
  key: options.getRowKey(vulnerability),
  publishedAtText: new Date(vulnerability.publishedAt).toLocaleString(),
  referenceUrls: vulnerability.references
    .slice(0, 3)
    .map((reference) => sanitizeUrl(reference))
    .filter((reference) => reference.length > 0),
  relatedComponents: options.relatedComponents.map((component) => ({
    evidence: sanitizeText(component.evidence),
    label: sanitizeText(component.version ? `${component.name} ${component.version}` : component.name)
  })),
  severityClassName: options.colorCodedSeverity ? `vulndash-${sanitizeText(vulnerability.severity).toLowerCase()}` : '',
  severityText: sanitizeText(vulnerability.severity),
  sourceText: sanitizeText(vulnerability.source),
  summaryMarkdown: sanitizeMarkdown(vulnerability.summary),
  titleText: sanitizeText(vulnerability.title)
});
