export class RowRegistry<TRow> {
  private readonly rows = new Map<string, TRow>();

  public clear(): void {
    this.rows.clear();
  }

  public delete(key: string): boolean {
    return this.rows.delete(key);
  }

  public entries(): IterableIterator<[string, TRow]> {
    return this.rows.entries();
  }

  public get(key: string): TRow | undefined {
    return this.rows.get(key);
  }

  public has(key: string): boolean {
    return this.rows.has(key);
  }

  public keys(): string[] {
    return Array.from(this.rows.keys());
  }

  public set(key: string, row: TRow): void {
    this.rows.set(key, row);
  }

  public values(): IterableIterator<TRow> {
    return this.rows.values();
  }
}
