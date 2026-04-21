import type { ManagedMarkdownSection } from '../../application/rollup/RollupMarkdownRenderer';

const MANAGED_MARKER_PREFIX = 'VULNDASH:SECTION';

const normalizeContent = (value: string): string =>
  value.replace(/\r\n/g, '\n').trim();

const buildStartMarker = (key: string): string =>
  `<!-- ${MANAGED_MARKER_PREFIX} ${key} START -->`;

const buildEndMarker = (key: string): string =>
  `<!-- ${MANAGED_MARKER_PREFIX} ${key} END -->`;

const escapeRegExp = (value: string): string =>
  value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export class MarkdownSectionMerger {
  public merge(input: {
    readonly analystNotesHeading: string;
    readonly analystNotesPlaceholder: string;
    readonly existingContent?: string | null;
    readonly managedSections: readonly ManagedMarkdownSection[];
    readonly title: string;
  }): string {
    const existingContent = normalizeContent(input.existingContent ?? '');
    const analystNotesBody =
      this.extractAnalystNotesBody(existingContent, input.analystNotesHeading)
      ?? input.analystNotesPlaceholder;
    const sections = input.managedSections.map((section) => this.renderManagedSection(section));

    return [
      input.title.trim(),
      '',
      ...sections.flatMap((section, index) =>
        index === sections.length - 1 ? [section] : [section, '']
      ),
      input.analystNotesHeading.trim(),
      '',
      analystNotesBody.trim() || input.analystNotesPlaceholder
    ].join('\n').trimEnd();
  }

  public renderManagedSection(section: ManagedMarkdownSection): string {
    return [
      buildStartMarker(section.key),
      normalizeContent(section.content),
      buildEndMarker(section.key)
    ].join('\n');
  }

  private extractAnalystNotesBody(
    content: string,
    analystNotesHeading: string
  ): string | null {
    if (!content) {
      return null;
    }

    const escapedHeading = escapeRegExp(analystNotesHeading.trim());
    const analystHeadingPattern = new RegExp(`^${escapedHeading}\\s*$`, 'm');

    const match = analystHeadingPattern.exec(content);
    if (!match || match.index === undefined) {
      return null;
    }

    const bodyStart = match.index + match[0].length;
    return content.slice(bodyStart).trim();
  }

  public replaceManagedSections(input: {
    readonly existingContent: string;
    readonly managedSections: readonly ManagedMarkdownSection[];
  }): string {
    let working = normalizeContent(input.existingContent);

    for (const section of input.managedSections) {
      const nextBlock = this.renderManagedSection(section);
      const pattern = new RegExp(
        `${escapeRegExp(buildStartMarker(section.key))}[\\s\\S]*?${escapeRegExp(buildEndMarker(section.key))}`,
        'm'
      );
      working = pattern.test(working)
        ? working.replace(pattern, nextBlock)
        : `${working.trimEnd()}\n\n${nextBlock}`;
    }

    return working;
  }
}
