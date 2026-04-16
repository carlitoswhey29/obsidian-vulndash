import type { ComponentRelationshipGraph, RelatedComponentSummary } from './types';

const START_MARKER = '<!-- vulndash:related-vulnerabilities:start -->';
const END_MARKER = '<!-- vulndash:related-vulnerabilities:end -->';

const formatComponentLabel = (component: RelatedComponentSummary): string =>
  component.version ? `${component.name} ${component.version}` : component.name;

const formatWikiLink = (path: string, label: string): string =>
  `[[${path.replace(/[\]|]/g, '')}|${label.replace(/[\]|]/g, '')}]]`;

const extractManagedLinks = (content: string): Array<{ label: string; notePath: string }> => {
  const match = content.match(new RegExp(`${START_MARKER}\\n([\\s\\S]*?)\\n${END_MARKER}`));
  if (!match?.[1]) {
    return [];
  }

  return match[1]
    .split('\n')
    .map((line) => line.match(/^- \[\[([^|\]]+)(?:\|([^\]]+))?\]\]$/))
    .filter((entry): entry is RegExpMatchArray => entry !== null)
    .map((entry) => ({
      label: (entry[2] ?? entry[1] ?? '').trim(),
      notePath: (entry[1] ?? '').trim()
    }))
    .filter((entry) => entry.notePath.length > 0);
};

export interface VulnerabilityNoteRelationshipContext {
  relatedComponentKeys: string[];
  relatedComponentNames: string[];
  relatedComponentNotePaths: string[];
  relatedComponentSectionLines: string[];
}

export class ComponentBacklinkService {
  public buildVulnerabilityNoteContext(
    vulnerabilityRef: string,
    graph: ComponentRelationshipGraph
  ): VulnerabilityNoteRelationshipContext {
    const relatedComponents = graph.componentsByVulnerability.get(vulnerabilityRef) ?? [];

    const relatedComponentKeys = relatedComponents.map((component) => component.key);
    const relatedComponentNames = relatedComponents.map((component) => formatComponentLabel(component));
    const relatedComponentNotePaths = relatedComponents
      .map((component) => component.notePath ?? '')
      .filter((notePath) => notePath.length > 0);
    const relatedComponentSectionLines = relatedComponents.length > 0
      ? relatedComponents.map((component) => {
        const label = formatComponentLabel(component);
        const base = component.notePath ? formatWikiLink(component.notePath, label) : label;
        return `- ${base} (${component.evidence})`;
      })
      : ['- None linked'];

    return {
      relatedComponentKeys,
      relatedComponentNames,
      relatedComponentNotePaths,
      relatedComponentSectionLines
    };
  }

  public upsertRelatedVulnerabilitySection(
    existingContent: string,
    links: ReadonlyArray<{ label: string; notePath: string }>
  ): string {
    const mergedLinks = [...extractManagedLinks(existingContent), ...links];
    const dedupedLinks = Array.from(new Map(mergedLinks
      .filter((link) => link.notePath.trim().length > 0)
      .map((link) => [link.notePath.trim().toLowerCase(), {
        label: link.label.trim(),
        notePath: link.notePath.trim()
      }] as const)).values())
      .sort((left, right) => left.label.localeCompare(right.label) || left.notePath.localeCompare(right.notePath));

    const section = dedupedLinks.length === 0
      ? ''
      : [
        START_MARKER,
        '## Related Vulnerabilities',
        ...dedupedLinks.map((link) => `- ${formatWikiLink(link.notePath, link.label)}`),
        END_MARKER
      ].join('\n');

    const pattern = new RegExp(`${START_MARKER}[\\s\\S]*?${END_MARKER}\\n?`, 'g');
    const stripped = existingContent.replace(pattern, '').trimEnd();

    if (!section) {
      return stripped;
    }

    return `${stripped}\n\n${section}\n`;
  }
}
