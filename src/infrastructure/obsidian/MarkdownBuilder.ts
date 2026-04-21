export type ObsidianCalloutType =
  | 'note'
  | 'abstract'
  | 'summary'
  | 'info'
  | 'todo'
  | 'tip'
  | 'success'
  | 'question'
  | 'help'
  | 'warning'
  | 'failure'
  | 'danger'
  | 'bug'
  | 'example'
  | 'quote';

export interface MarkdownTable {
  headers: string[];
  rows: Array<Array<string | number | boolean | null | undefined>>;
}

export class MarkdownBuilder {
  private readonly lines: string[] = [];

  public h1(text: string): this {
    return this.heading(1, text);
  }

  public h2(text: string): this {
    return this.heading(2, text);
  }

  public h3(text: string): this {
    return this.heading(3, text);
  }

  public h4(text: string): this {
    return this.heading(4, text);
  }

  public h5(text: string): this {
    return this.heading(5, text);
  }

  public h6(text: string): this {
    return this.heading(6, text);
  }

  public heading(level: 1 | 2 | 3 | 4 | 5 | 6, text: string): this {
    const normalized = this.normalizeInline(text);
    if (!normalized) {
      return this;
    }

    this.ensureBlockSeparation();
    this.lines.push(`${'#'.repeat(level)} ${normalized}`);
    this.lines.push('');
    return this;
  }

  public paragraph(text: string): this {
    const normalizedLines = this.normalizeMultiline(text).filter((line) => line.trim().length > 0);
    if (normalizedLines.length === 0) {
      return this;
    }

    this.ensureBlockSeparation();
    this.lines.push(...normalizedLines);
    this.lines.push('');
    return this;
  }

  public line(text: string): this {
    const normalized = this.normalizeInline(text);
    if (!normalized) {
      return this;
    }

    this.lines.push(normalized);
    return this;
  }

  public raw(text: string): this {
    const normalizedLines = this.normalizeMultiline(text);
    if (normalizedLines.length === 0) {
      return this;
    }

    this.lines.push(...normalizedLines);
    return this;
  }

  public emptyLine(): this {
    if (this.lines.length === 0 || this.lines[this.lines.length - 1] === '') {
      return this;
    }

    this.lines.push('');
    return this;
  }

  public callout(
    type: ObsidianCalloutType,
    title: string,
    contentLines: string[] = []
  ): this {
    const normalizedTitle = this.normalizeInline(title);
    const normalizedContent = contentLines
      .flatMap((line) => this.normalizeMultiline(line))
      .filter((line) => line.trim().length > 0);

    this.ensureBlockSeparation();
    this.lines.push(`> [!${type}]${normalizedTitle ? ` ${normalizedTitle}` : ''}`);

    if (normalizedContent.length === 0) {
      this.lines.push('> ');
    } else {
      for (const line of normalizedContent) {
        this.lines.push(`> ${line}`);
      }
    }

    this.lines.push('');
    return this;
  }

  public blockquote(text: string | string[]): this {
    const normalizedLines = Array.isArray(text)
      ? text.flatMap((line) => this.normalizeMultiline(line))
      : this.normalizeMultiline(text);

    const content = normalizedLines.filter((line) => line.trim().length > 0);
    if (content.length === 0) {
      return this;
    }

    this.ensureBlockSeparation();
    for (const line of content) {
      this.lines.push(`> ${line}`);
    }
    this.lines.push('');
    return this;
  }

  public unorderedList(items: Array<string | null | undefined>): this {
    const normalizedItems = items
      .filter((item): item is string => typeof item === 'string')
      .flatMap((item) => this.normalizeMultiline(item))
      .map((item) => item.trim())
      .filter((item) => item.length > 0);

    if (normalizedItems.length === 0) {
      return this;
    }

    this.ensureBlockSeparation();
    for (const item of normalizedItems) {
      this.lines.push(`- ${item}`);
    }
    this.lines.push('');
    return this;
  }

  public orderedList(items: Array<string | null | undefined>, startAt = 1): this {
    const normalizedItems = items
      .filter((item): item is string => typeof item === 'string')
      .flatMap((item) => this.normalizeMultiline(item))
      .map((item) => item.trim())
      .filter((item) => item.length > 0);

    if (normalizedItems.length === 0) {
      return this;
    }

    this.ensureBlockSeparation();
    let index = startAt;
    for (const item of normalizedItems) {
      this.lines.push(`${index}. ${item}`);
      index += 1;
    }
    this.lines.push('');
    return this;
  }

  public definitionList(items: Array<{ term: string; description: string }>): this {
    const normalizedItems = items
      .map((item) => ({
        term: this.normalizeInline(item.term),
        description: this.normalizeInline(item.description)
      }))
      .filter((item) => item.term.length > 0 && item.description.length > 0);

    if (normalizedItems.length === 0) {
      return this;
    }

    this.ensureBlockSeparation();
    for (const item of normalizedItems) {
      this.lines.push(
        `- **${MarkdownBuilder.escapeInline(item.term)}:** ${item.description}`
      );
    }
    this.lines.push('');
    return this;
  }

  public table(table: MarkdownTable): this {
    const headers = table.headers.map((header) => this.escapeTableCell(this.normalizeInline(header)));
    if (headers.length === 0) {
      return this;
    }

    const rows = table.rows.map((row) => {
      const padded = [...row];
      while (padded.length < headers.length) {
        padded.push('');
      }

      return padded
        .slice(0, headers.length)
        .map((cell) => this.escapeTableCell(this.stringifyCell(cell)));
    });

    this.ensureBlockSeparation();
    this.lines.push(`| ${headers.join(' | ')} |`);
    this.lines.push(`| ${headers.map(() => '---').join(' | ')} |`);

    for (const row of rows) {
      this.lines.push(`| ${row.join(' | ')} |`);
    }

    this.lines.push('');
    return this;
  }

  public codeFence(code: string, language?: string): this {
    const normalizedCode = code.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const safeLanguage = this.normalizeFenceLanguage(language);

    this.ensureBlockSeparation();
    this.lines.push(`\`\`\`${safeLanguage}`);
    this.lines.push(...normalizedCode.split('\n'));
    this.lines.push('```');
    this.lines.push('');
    return this;
  }

  public horizontalRule(): this {
    this.ensureBlockSeparation();
    this.lines.push('---');
    this.lines.push('');
    return this;
  }

  public appendIf(condition: boolean, fn: (builder: this) => void): this {
    if (condition) {
      fn(this);
    }
    return this;
  }

  public append(builder: MarkdownBuilder): this {
    const built = builder.build();
    if (!built) {
      return this;
    }

    this.ensureBlockSeparation();
    this.lines.push(...built.split('\n'));
    return this;
  }

  public build(): string {
    return this.lines.join('\n').trimEnd();
  }

  public static bold(text: string): string {
    return `**${MarkdownBuilder.escapeInline(text)}**`;
  }

  public static italic(text: string): string {
    return `*${MarkdownBuilder.escapeInline(text)}*`;
  }

  public static strikethrough(text: string): string {
    return `~~${MarkdownBuilder.escapeInline(text)}~~`;
  }

  public static inlineCode(text: string): string {
    const normalized = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const escaped = normalized.replace(/`/g, '\\`');
    return `\`${escaped}\``;
  }

  public static link(label: string, url: string, title?: string): string {
    const safeLabel = MarkdownBuilder.escapeInline(label.trim());
    const safeUrl = MarkdownBuilder.sanitizeUrl(url);
    const safeTitle = title?.trim() ? ` "${title.replace(/"/g, '&quot;')}"` : '';

    if (!safeLabel || !safeUrl) {
      return safeLabel || '';
    }

    return `[${safeLabel}](${safeUrl}${safeTitle})`;
  }

  private ensureBlockSeparation(): void {
    if (this.lines.length === 0) {
      return;
    }

    if (this.lines[this.lines.length - 1] !== '') {
      this.lines.push('');
    }
  }

  private normalizeInline(text: string): string {
    return MarkdownBuilder.normalizeInlineStatic(text);
  }

  private normalizeMultiline(text: string): string[] {
    return text
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .split('\n')
      .map((line) => line.trimEnd());
  }

  private stringifyCell(value: string | number | boolean | null | undefined): string {
    if (value === null || value === undefined) {
      return '';
    }

    if (typeof value === 'boolean') {
      return value ? 'Yes' : 'No';
    }

    return this.normalizeInline(String(value));
  }

  private escapeTableCell(value: string): string {
    return value.replace(/\|/g, '\\|');
  }

  private normalizeFenceLanguage(language?: string): string {
    if (!language) {
      return '';
    }

    return language.trim().replace(/[^\w+-]/g, '');
  }

  private static normalizeInlineStatic(text: string): string {
    return text
      .replace(/\r\n/g, '\n')
      .replace(/\r/g, '\n')
      .replace(/\n+/g, ' ')
      .trim();
  }

  private static escapeInline(text: string): string {
    return text.replace(/[\\`*_{}[\]()#+.!-]/g, '\\$&');
  }

  private static sanitizeUrl(url: string): string {
    const trimmed = url.trim();
    if (!trimmed) {
      return '';
    }

    try {
      const parsed = new URL(trimmed);
      if (!['http:', 'https:', 'mailto:'].includes(parsed.protocol)) {
        return '';
      }

      return parsed.toString();
    } catch {
      return '';
    }
  }
}
