import { normalizePath } from 'obsidian';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import type { ImportedSbomConfig, RuntimeSbomComponent, RuntimeSbomState, VulnDashSettings } from './types';

interface SbomReader {
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
}

interface CycloneDxComponent {
  components?: CycloneDxComponent[];
  name?: unknown;
}

interface CycloneDxDocument {
  bomFormat?: unknown;
  components?: CycloneDxComponent[];
  metadata?: {
    component?: CycloneDxComponent;
  };
  specVersion?: unknown;
}

export interface SbomLoadSuccessResult {
  fromCache: boolean;
  sbomId: string;
  state: RuntimeSbomState;
  success: true;
}

export interface SbomLoadFailureResult {
  cachedState: RuntimeSbomState | null;
  error: string;
  sbomId: string;
  success: false;
}

export type SbomLoadResult = SbomLoadSuccessResult | SbomLoadFailureResult;

export interface SbomFileChangeStatus {
  currentHash: string | null;
  error: string | null;
  status: 'changed' | 'error' | 'missing' | 'not-imported' | 'unchanged';
}

export interface SbomValidationSuccessResult {
  componentCount: number;
  normalizedPath: string;
  success: true;
}

export interface SbomValidationFailureResult {
  error: string;
  normalizedPath: string;
  success: false;
}

export type SbomValidationResult = SbomValidationSuccessResult | SbomValidationFailureResult;

export class SbomImportService {
  private readonly nameNormalizer: ProductNameNormalizer;
  private readonly reader: SbomReader;
  private readonly runtimeCache = new Map<string, RuntimeSbomState>();

  public constructor(reader: SbomReader, nameNormalizer = new ProductNameNormalizer()) {
    this.reader = reader;
    this.nameNormalizer = nameNormalizer;
  }

  public async loadAllSboms(settings: Pick<VulnDashSettings, 'sboms'>): Promise<SbomLoadResult[]> {
    const enabledSboms = settings.sboms.filter((sbom) => sbom.enabled);
    return Promise.all(enabledSboms.map((sbom) => this.loadSbom(sbom)));
  }

  public async loadSbom(config: ImportedSbomConfig, options?: { force?: boolean }): Promise<SbomLoadResult> {
    const normalizedPath = this.normalizeSbomPath(config.path);
    const cached = this.runtimeCache.get(config.id) ?? null;

    if (!normalizedPath) {
      return {
        cachedState: cached,
        error: 'SBOM path is required.',
        sbomId: config.id,
        success: false
      };
    }

    if (!options?.force && cached && cached.sourcePath === normalizedPath) {
      return {
        fromCache: true,
        sbomId: config.id,
        state: cached,
        success: true
      };
    }

    try {
      const raw = await this.reader.read(normalizedPath);
      const parsed = this.parseSbom(raw);
      const state: RuntimeSbomState = {
        components: this.extractComponents(parsed),
        hash: await this.hashContent(raw),
        lastError: null,
        lastLoadedAt: Date.now(),
        sourcePath: normalizedPath
      };

      this.runtimeCache.set(config.id, state);
      return {
        fromCache: false,
        sbomId: config.id,
        state,
        success: true
      };
    } catch (error) {
      return {
        cachedState: cached,
        error: this.getErrorMessage(error),
        sbomId: config.id,
        success: false
      };
    }
  }

  public getRuntimeState(sbomId: string): RuntimeSbomState | null {
    return this.runtimeCache.get(sbomId) ?? null;
  }

  public getRuntimeCacheSnapshot(): Map<string, RuntimeSbomState> {
    return new Map(this.runtimeCache);
  }

  public invalidateCache(sbomId: string): void {
    this.runtimeCache.delete(sbomId);
  }

  public async getFileChangeStatus(config: ImportedSbomConfig): Promise<SbomFileChangeStatus> {
    const normalizedPath = this.normalizeSbomPath(config.path);
    if (!normalizedPath) {
      return {
        currentHash: null,
        error: 'SBOM path is required.',
        status: 'error'
      };
    }

    try {
      const exists = await this.reader.exists(normalizedPath);
      if (!exists) {
        return {
          currentHash: null,
          error: 'SBOM file not found.',
          status: 'missing'
        };
      }

      const raw = await this.reader.read(normalizedPath);
      const currentHash = await this.hashContent(raw);
      if (!config.contentHash) {
        return {
          currentHash,
          error: null,
          status: 'not-imported'
        };
      }

      return {
        currentHash,
        error: null,
        status: currentHash === config.contentHash ? 'unchanged' : 'changed'
      };
    } catch (error) {
      return {
        currentHash: null,
        error: this.getErrorMessage(error),
        status: 'error'
      };
    }
  }

  public async validateSbomPath(path: string): Promise<SbomValidationResult> {
    const normalizedPath = this.normalizeSbomPath(path);
    if (!normalizedPath) {
      return {
        error: 'Choose a JSON SBOM file from your vault.',
        normalizedPath,
        success: false
      };
    }

    try {
      const exists = await this.reader.exists(normalizedPath);
      if (!exists) {
        return {
          error: 'The selected SBOM file could not be found in the vault.',
          normalizedPath,
          success: false
        };
      }

      const raw = await this.reader.read(normalizedPath);
      const parsed = this.parseSbom(raw);
      if (!this.looksLikeCycloneDxDocument(parsed)) {
        return {
          error: 'The selected file is valid JSON, but it does not look like a CycloneDX SBOM.',
          normalizedPath,
          success: false
        };
      }

      return {
        componentCount: this.extractComponents(parsed).length,
        normalizedPath,
        success: true
      };
    } catch (error) {
      return {
        error: this.getErrorMessage(error),
        normalizedPath,
        success: false
      };
    }
  }

  private parseSbom(raw: string): CycloneDxDocument {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('SBOM file is not a valid JSON object.');
    }

    return parsed as CycloneDxDocument;
  }

  private extractComponents(document: CycloneDxDocument): RuntimeSbomComponent[] {
    const deduped = new Map<string, RuntimeSbomComponent>();

    for (const component of this.flattenComponents(document)) {
      const originalName = this.getString(component.name);
      if (!originalName) {
        continue;
      }

      const normalizedName = this.nameNormalizer.normalize(originalName);
      const effectiveName = normalizedName || originalName;
      const key = originalName.toLowerCase();
      if (!deduped.has(key)) {
        deduped.set(key, {
          normalizedName: effectiveName,
          originalName
        });
      }
    }

    return Array.from(deduped.values()).sort((left, right) =>
      left.normalizedName.localeCompare(right.normalizedName) || left.originalName.localeCompare(right.originalName));
  }

  private flattenComponents(document: CycloneDxDocument): CycloneDxComponent[] {
    const queue: CycloneDxComponent[] = [];
    if (document.metadata?.component) {
      queue.push(document.metadata.component);
    }
    if (Array.isArray(document.components)) {
      queue.push(...document.components);
    }

    const flattened: CycloneDxComponent[] = [];
    while (queue.length > 0) {
      const component = queue.shift();
      if (!component) {
        continue;
      }

      flattened.push(component);
      if (Array.isArray(component.components)) {
        queue.push(...component.components);
      }
    }

    return flattened;
  }

  private looksLikeCycloneDxDocument(document: CycloneDxDocument): boolean {
    if (this.getString(document.bomFormat).toLowerCase() === 'cyclonedx') {
      return true;
    }

    if (this.getString(document.specVersion)) {
      return true;
    }

    if (Array.isArray(document.components) || document.metadata?.component) {
      return true;
    }

    return false;
  }

  private async hashContent(content: string): Promise<string> {
    const buffer = new TextEncoder().encode(content);
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  private normalizeSbomPath(path: string): string {
    const trimmed = path.trim();
    return trimmed ? normalizePath(trimmed) : '';
  }

  private getString(value: unknown): string {
    return typeof value === 'string' ? value.trim() : '';
  }

  private getErrorMessage(error: unknown): string {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }

    return 'Unable to load SBOM.';
  }
}
