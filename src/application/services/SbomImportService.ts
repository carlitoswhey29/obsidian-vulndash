import { normalizePath } from 'obsidian';
import { ProductNameNormalizer } from '../../domain/services/ProductNameNormalizer';
import type { ImportedSbomComponent, ImportedSbomConfig } from './types';

interface SbomReader {
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
}

interface CycloneDxComponent {
  'bom-ref'?: unknown;
  bomRef?: unknown;
  cpe?: unknown;
  group?: unknown;
  name?: unknown;
  purl?: unknown;
  version?: unknown;
  components?: CycloneDxComponent[];
}

interface CycloneDxDocument {
  metadata?: {
    component?: CycloneDxComponent;
  };
  components?: CycloneDxComponent[];
}

export interface SbomImportSuccessResult {
  success: true;
  sbom: ImportedSbomConfig;
  importedComponentCount: number;
}

export interface SbomImportFailureResult {
  success: false;
  error: string;
}

export type SbomImportResult = SbomImportSuccessResult | SbomImportFailureResult;

export interface SbomFileChangeStatus {
  currentHash: string | null;
  error: string | null;
  status: 'changed' | 'error' | 'missing' | 'not-imported' | 'unchanged';
}

export class SbomImportService {
  private readonly nameNormalizer: ProductNameNormalizer;
  private readonly reader: SbomReader;

  public constructor(reader: SbomReader, nameNormalizer = new ProductNameNormalizer()) {
    this.reader = reader;
    this.nameNormalizer = nameNormalizer;
  }

  public async importSbom(config: ImportedSbomConfig): Promise<SbomImportResult> {
    const normalizedPath = this.normalizeSbomPath(config.path);
    if (!normalizedPath) {
      return { success: false, error: 'SBOM path is required.' };
    }

    try {
      const raw = await this.reader.read(normalizedPath);
      const parsed = this.parseSbom(raw);
      const hash = await this.hashContent(raw);
      const components = this.buildImportedComponents(parsed, config);

      return {
        success: true,
        sbom: {
          ...config,
          path: normalizedPath,
          components,
          lastImportedAt: Date.now(),
          lastImportError: null,
          lastImportHash: hash
        },
        importedComponentCount: components.length
      };
    } catch (error) {
      return {
        success: false,
        error: this.getErrorMessage(error)
      };
    }
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
      if (!config.lastImportHash) {
        return {
          currentHash,
          error: null,
          status: 'not-imported'
        };
      }

      return {
        currentHash,
        error: null,
        status: currentHash === config.lastImportHash ? 'unchanged' : 'changed'
      };
    } catch (error) {
      return {
        currentHash: null,
        error: this.getErrorMessage(error),
        status: 'error'
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

  private buildImportedComponents(document: CycloneDxDocument, config: ImportedSbomConfig): ImportedSbomComponent[] {
    const previousComponents = new Map(
      config.components.map((component) => [this.buildComponentIdentityKey(component), component] as const)
    );
    const deduped = new Map<string, ImportedSbomComponent>();
    const sourceComponents = this.flattenComponents(document);

    for (const sourceComponent of sourceComponents) {
      const imported = this.mapImportedComponent(sourceComponent, config, previousComponents, deduped.size);
      if (!imported) {
        continue;
      }

      const identityKey = this.buildComponentIdentityKey(imported);
      if (!deduped.has(identityKey)) {
        deduped.set(identityKey, imported);
      }
    }

    return Array.from(deduped.values()).sort((left, right) =>
      left.normalizedName.localeCompare(right.normalizedName)
      || left.version.localeCompare(right.version)
      || left.name.localeCompare(right.name));
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

  private mapImportedComponent(
    sourceComponent: CycloneDxComponent,
    config: ImportedSbomConfig,
    previousComponents: Map<string, ImportedSbomComponent>,
    index: number
  ): ImportedSbomComponent | null {
    const name = this.getString(sourceComponent.name);
    const version = this.getString(sourceComponent.version);
    const purl = this.getString(sourceComponent.purl);
    const cpe = this.getString(sourceComponent.cpe);
    const bomRef = this.getString(sourceComponent['bom-ref']) || this.getString(sourceComponent.bomRef);
    const namespace = this.getComponentNamespace(sourceComponent, purl, config.namespace);
    const normalizedName = this.nameNormalizer.normalize(name || cpe || purl || bomRef);
    const displayName = name || normalizedName || purl || cpe || bomRef;

    if (!displayName || !normalizedName) {
      return null;
    }

    const importIdentity = this.buildSourceIdentityKey({
      bomRef,
      cpe,
      name: displayName,
      normalizedName,
      namespace,
      purl,
      version
    });
    const previous = previousComponents.get(importIdentity);

    return {
      id: previous?.id ?? `component-${index + 1}`,
      name: previous?.name?.trim() || displayName,
      normalizedName: previous?.normalizedName?.trim() || normalizedName,
      version,
      purl,
      cpe,
      bomRef,
      namespace,
      enabled: previous?.enabled ?? true,
      excluded: previous?.excluded ?? false
    };
  }

  private buildSourceIdentityKey(component: {
    bomRef: string;
    cpe: string;
    name: string;
    normalizedName: string;
    namespace: string;
    purl: string;
    version: string;
  }): string {
    const primaryIdentity = [
      component.bomRef.toLowerCase(),
      component.purl.toLowerCase(),
      component.cpe.toLowerCase()
    ].filter(Boolean);

    if (primaryIdentity.length > 0) {
      return [
        ...primaryIdentity,
        component.namespace.toLowerCase(),
        component.version.toLowerCase()
      ].join('|');
    }

    return [
      component.namespace.toLowerCase(),
      component.normalizedName.toLowerCase(),
      component.version.toLowerCase()
    ].join('|');
  }

  private buildComponentIdentityKey(component: ImportedSbomComponent): string {
    return this.buildSourceIdentityKey({
      bomRef: component.bomRef,
      cpe: component.cpe,
      name: component.name,
      normalizedName: component.normalizedName,
      namespace: component.namespace,
      purl: component.purl,
      version: component.version
    });
  }

  private getComponentNamespace(component: CycloneDxComponent, purl: string, sbomNamespace: string): string {
    const explicitNamespace = this.getString(component.group);
    if (explicitNamespace) {
      return explicitNamespace;
    }

    const purlNamespace = this.getPurlNamespace(purl);
    if (purlNamespace) {
      return purlNamespace;
    }

    return sbomNamespace.trim();
  }

  private getPurlNamespace(purl: string): string {
    if (!purl.startsWith('pkg:')) {
      return '';
    }

    const purlWithoutScheme = purl.slice(4);
    const typeSeparatorIndex = purlWithoutScheme.indexOf('/');
    if (typeSeparatorIndex === -1) {
      return '';
    }

    const pathWithVersion = purlWithoutScheme.slice(typeSeparatorIndex + 1);
    const path = pathWithVersion.split('@')[0] ?? '';
    const segments = path.split('/').filter(Boolean);
    if (segments.length <= 1) {
      return '';
    }

    return decodeURIComponent(segments.slice(0, -1).join('/'));
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

    return 'Unable to import SBOM.';
  }
}
