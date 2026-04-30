import { normalizePath } from 'obsidian';
import { SbomParserFactory } from '../../infrastructure/parsers/SbomParserFactory';
import type { NormalizedSbomDocument } from '../../domain/sbom/types';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import { AsyncTaskCoordinator } from '../../infrastructure/async/AsyncTaskCoordinator';
import { CooperativeScheduler } from '../../infrastructure/async/CooperativeScheduler';
import type { ComponentNoteLookupInput } from '../sbom/ComponentStorageResolver';
import type { ImportedSbomConfig, RuntimeSbomComponent, RuntimeSbomState, VulnDashSettings } from './types';

interface SbomReader {
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
}

export interface SbomComponentNotePathResolver {
  resolve(component: ComponentNoteLookupInput): string | null;
}

export interface SbomComponentNotePathResolverFactory {
  createResolver(): SbomComponentNotePathResolver;
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

export interface SbomImportServiceOptions {
  readonly asyncTaskCoordinator?: AsyncTaskCoordinator;
  readonly cooperativeScheduler?: CooperativeScheduler;
  readonly notePathItemsPerYield?: number;
  readonly parserFactory?: Pick<SbomParserFactory, 'parse'>;
  readonly runtimeComponentItemsPerYield?: number;
  readonly workerMinimumBytes?: number;
}

const DEFAULT_NOTE_PATH_ITEMS_PER_YIELD = 100;
const DEFAULT_RUNTIME_COMPONENT_ITEMS_PER_YIELD = 150;
const DEFAULT_SBOM_WORKER_MINIMUM_BYTES = 512 * 1024;

export class SbomImportService {
  private readonly asyncTaskCoordinator: AsyncTaskCoordinator;
  private readonly cooperativeScheduler: CooperativeScheduler;
  private readonly nameNormalizer: ProductNameNormalizer;
  private readonly notePathItemsPerYield: number;
  private readonly notePathResolverFactory: SbomComponentNotePathResolverFactory | null;
  private readonly parserFactory: Pick<SbomParserFactory, 'parse'>;
  private readonly reader: SbomReader;
  private readonly runtimeCache = new Map<string, RuntimeSbomState>();
  private readonly runtimeComponentItemsPerYield: number;
  private readonly workerMinimumBytes: number;

  public constructor(
    reader: SbomReader,
    nameNormalizer = new ProductNameNormalizer(),
    notePathResolverFactory: SbomComponentNotePathResolverFactory | null = null,
    options: SbomImportServiceOptions = {}
  ) {
    this.reader = reader;
    this.nameNormalizer = nameNormalizer;
    this.notePathResolverFactory = notePathResolverFactory;
    this.asyncTaskCoordinator = options.asyncTaskCoordinator ?? new AsyncTaskCoordinator();
    this.cooperativeScheduler = options.cooperativeScheduler ?? new CooperativeScheduler();
    this.notePathItemsPerYield = options.notePathItemsPerYield ?? DEFAULT_NOTE_PATH_ITEMS_PER_YIELD;
    this.parserFactory = options.parserFactory ?? new SbomParserFactory();
    this.runtimeComponentItemsPerYield = options.runtimeComponentItemsPerYield ?? DEFAULT_RUNTIME_COMPONENT_ITEMS_PER_YIELD;
    this.workerMinimumBytes = options.workerMinimumBytes ?? DEFAULT_SBOM_WORKER_MINIMUM_BYTES;
  }

  public async loadAllSboms(settings: Pick<VulnDashSettings, 'sboms'>): Promise<SbomLoadResult[]> {
    const enabledSboms = settings.sboms.filter((sbom) => sbom.enabled);
    const notePathResolver = this.createNotePathResolver();
    return Promise.all(enabledSboms.map((sbom) => this.loadSbom(sbom, { notePathResolver })));
  }

  public async loadSbom(
    config: ImportedSbomConfig,
    options?: {
      force?: boolean;
      notePathResolver?: SbomComponentNotePathResolver | null;
    }
  ): Promise<SbomLoadResult> {
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

    const loadToken = this.asyncTaskCoordinator.beginToken(this.getLoadTokenKey(config.id));

    try {
      const raw = await this.reader.read(normalizedPath);
      if (!this.asyncTaskCoordinator.isCurrent(loadToken)) {
        return this.buildStaleLoadResult(config.id, cached);
      }

      const parsed = await this.parseSbom(
        raw,
        normalizedPath,
        options?.notePathResolver ?? this.createNotePathResolver()
      );
      if (!this.asyncTaskCoordinator.isCurrent(loadToken)) {
        return this.buildStaleLoadResult(config.id, cached);
      }

      const state: RuntimeSbomState = {
        components: parsed.components,
        document: parsed.document,
        hash: await this.hashContent(raw),
        lastError: null,
        lastLoadedAt: Date.now(),
        sourcePath: normalizedPath
      };

      if (!this.asyncTaskCoordinator.isCurrent(loadToken)) {
        return this.buildStaleLoadResult(config.id, cached);
      }

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
    } finally {
      this.asyncTaskCoordinator.releaseToken(loadToken);
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

  public invalidateAllCaches(): void {
    this.runtimeCache.clear();
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
      const parsed = await this.parseSbom(raw, normalizedPath, null);

      return {
        componentCount: parsed.document.components.length,
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

  private async applyNotePaths(
    document: NormalizedSbomDocument,
    notePathResolver: SbomComponentNotePathResolver
  ): Promise<NormalizedSbomDocument> {
    const components = await this.cooperativeScheduler.mapInBatches(document.components, (component) => {
      const noteInput: ComponentNoteLookupInput = {
        name: component.name
      };
      if (component.cpe) {
        noteInput.cpe = component.cpe;
      }
      if (component.purl) {
        noteInput.purl = component.purl;
      }
      if (component.version) {
        noteInput.version = component.version;
      }

      const notePath = notePathResolver.resolve(noteInput);
      if (notePath === undefined) {
        return component;
      }

      return {
        ...component,
        notePath
      };
    }, {
      itemsPerYield: this.notePathItemsPerYield,
      timeoutMs: 16
    });

    return {
      ...document,
      components
    };
  }

  private buildStaleLoadResult(sbomId: string, cachedState: RuntimeSbomState | null): SbomLoadResult {
    const current = this.runtimeCache.get(sbomId) ?? cachedState;
    if (current) {
      return {
        fromCache: true,
        sbomId,
        state: current,
        success: true
      };
    }

    return {
      cachedState: null,
      error: 'A newer SBOM load completed first.',
      sbomId,
      success: false
    };
  }

  private createNotePathResolver(): SbomComponentNotePathResolver | null {
    if (!this.notePathResolverFactory) {
      return null;
    }

    return this.notePathResolverFactory.createResolver();
  }

  private async extractComponents(document: NormalizedSbomDocument): Promise<RuntimeSbomComponent[]> {
    const deduped = new Map<string, RuntimeSbomComponent>();
    let processedSinceYield = 0;

    for (const component of document.components) {
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

      processedSinceYield += 1;
      if (processedSinceYield >= this.runtimeComponentItemsPerYield) {
        processedSinceYield = 0;
        await this.cooperativeScheduler.yieldToHost({ timeoutMs: 16 });
      }
    }

    return Array.from(deduped.values()).sort((left, right) =>
      left.normalizedName.localeCompare(right.normalizedName) || left.originalName.localeCompare(right.originalName));
  }

  private getLoadTokenKey(sbomId: string): string {
    return `sbom-load:${sbomId}`;
  }

  private async hashContent(content: string): Promise<string> {
    const buffer = new TextEncoder().encode(content);
    const digest = await crypto.subtle.digest('SHA-256', buffer);
    const bytes = Array.from(new Uint8Array(digest));
    return bytes.map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  private getBasename(path: string): string {
    const segments = normalizePath(path).split('/').filter((segment) => segment.length > 0);
    const filename = segments.at(-1) ?? 'sbom.json';
    const lastDotIndex = filename.lastIndexOf('.');

    return lastDotIndex > 0 ? filename.slice(0, lastDotIndex) : filename;
  }

  private getErrorMessage(error: unknown): string {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }

    return 'Unable to load SBOM.';
  }

  private getString(value: unknown): string {
    return typeof value === 'string' ? value.trim() : '';
  }

  private normalizeSbomPath(path: string): string {
    const trimmed = path.trim();
    return trimmed ? normalizePath(trimmed) : '';
  }

  private async parseSbom(
    raw: string,
    sourcePath: string,
    notePathResolver: SbomComponentNotePathResolver | null
  ): Promise<{
    components: RuntimeSbomComponent[];
    document: NormalizedSbomDocument;
  }> {
    const source = {
      basename: this.getBasename(sourcePath),
      path: sourcePath
    };
    const parseResult = await this.asyncTaskCoordinator.execute('parse-sbom', {
      raw,
      source
    }, {
      fallback: async ({ raw: fallbackRaw, source: fallbackSource }) => {
        const parsed = JSON.parse(fallbackRaw) as unknown;
        if (!parsed || typeof parsed !== 'object') {
          throw new Error('SBOM file is not a valid JSON object.');
        }

        return {
          document: this.parserFactory.parse(parsed, { source: fallbackSource })
        };
      },
      preferWorker: raw.length >= this.workerMinimumBytes
    });

    const document = notePathResolver
      ? await this.applyNotePaths(parseResult.document, notePathResolver)
      : parseResult.document;

    return {
      components: await this.extractComponents(document),
      document
    };
  }
}
