import { ResolveAffectedProjects } from './correlation/ResolveAffectedProjects';
import type { ImportedSbomConfig, VulnDashSettings } from './use-cases/types';
import { SettingsMigrator, type SettingsMigrationInput } from './settings/SettingsMigrator';
import { AlertEngine } from './use-cases/EvaluateAlertsUseCase';
import { ComponentInventoryService } from './sbom/ComponentInventoryService';
import { ComponentPreferenceService } from './sbom/ComponentPreferenceService';
import { ComponentVulnerabilityLinkService } from './sbom/ComponentVulnerabilityLinkService';
import { RelationshipNormalizer } from './sbom/RelationshipNormalizer';
import { SbomCatalogService } from './sbom/SbomCatalogService';
import { SbomComparisonService } from './use-cases/SbomComparisonService';
import { SbomFilterMergeService } from './use-cases/SbomFilterMergeService';
import { SbomImportService, type SbomComponentNotePathResolverFactory } from './use-cases/SbomImportService';
import { VulnerabilitySyncService } from './use-cases/SyncVulnerabilitiesUseCase';
import type { Vulnerability } from '../domain/entities/Vulnerability';
import type { PipelineEvent } from './pipeline/PipelineEvents';
import type { IHttpClient } from './ports/HttpClient';
import { SbomComponentIndex } from '../infrastructure/correlation/SbomComponentIndex';
import { buildFeedsFromConfig } from '../infrastructure/factories/FeedFactory';
import { HttpClient } from '../infrastructure/clients/common/HttpClient';
import { ProjectNoteLookupService, type ProjectNoteOption } from '../infrastructure/obsidian/ProjectNoteLookupService';
import type { ProjectNoteLookupResult } from './correlation/ResolveAffectedProjects';
import { SbomProjectMappingRepository } from '../infrastructure/storage/SbomProjectMappingRepository';
import { DailyRollupGenerator } from './rollup/DailyRollupGenerator';
import { SelectRollupFindings } from './rollup/SelectRollupFindings';
import { RollupMarkdownRenderer } from './rollup/RollupMarkdownRenderer';
import { DailyRollupNoteWriter } from '../infrastructure/obsidian/DailyRollupNoteWriter';
import { ComponentNoteResolverFactory } from '../infrastructure/obsidian-adapters/ObsidianNoteResolver';
import { CooperativeScheduler } from '../infrastructure/async/CooperativeScheduler';
import { CacheHydrator } from '../infrastructure/storage/CacheHydrator';
import { CachePruner } from '../infrastructure/storage/CachePruner';
import { IndexedDbTriageRepository } from '../infrastructure/storage/IndexedDbTriageRepository';
import { JoinTriageState } from './triage/JoinTriageState';
import { LegacyDataMigration } from '../infrastructure/storage/LegacyDataMigration';
import { SetTriageState } from './triage/SetTriageState';
import { SyncMetadataRepository } from '../infrastructure/storage/SyncMetadataRepository';
import { VulnCacheDb } from '../infrastructure/storage/VulnCacheDb';
import { VulnCacheRepository } from '../infrastructure/storage/VulnCacheRepository';
import type { IOsvQueryCache } from '../infrastructure/clients/osv/IOsvQueryCache';

type ProjectNoteLookupVaultFacade = ConstructorParameters<typeof ProjectNoteLookupService>[0];
type ComponentNoteResolverVaultFacade = ConstructorParameters<typeof ComponentNoteResolverFactory>[0];
type ComponentNoteResolverMetadataCacheFacade = ConstructorParameters<typeof ComponentNoteResolverFactory>[1];

export interface VulnDashVaultAdapter {
  exists(path: string): Promise<boolean>;
  read(path: string): Promise<string>;
  write(path: string, content: string): Promise<void>;
}

export type VulnDashVaultFacade = ProjectNoteLookupVaultFacade & ComponentNoteResolverVaultFacade & {
  readonly adapter: VulnDashVaultAdapter;
  create(path: string, content: string): Promise<unknown>;
  createFolder(path: string): Promise<unknown>;
};

export type VulnDashMetadataCacheFacade = ComponentNoteResolverMetadataCacheFacade;

export interface PersistentCacheServices {
  readonly cacheDb: VulnCacheDb;
  readonly cacheHydrator: CacheHydrator;
  readonly cachePruner: CachePruner;
  readonly cacheRepository: VulnCacheRepository;
  readonly metadataRepository: SyncMetadataRepository;
  readonly triageRepository: IndexedDbTriageRepository;
}

export interface PersistentCacheInitializationResult {
  readonly cachedVulnerabilities: readonly Vulnerability[];
  readonly lastFetchAt: number;
  readonly persistentCacheServices: PersistentCacheServices | null;
  readonly removedLegacyFields: boolean;
  readonly triageJoinUseCase: JoinTriageState | null;
  readonly triageSetUseCase: SetTriageState | null;
}

export interface CreateSyncServiceOptions {
  readonly cachedVulnerabilities: readonly Vulnerability[];
  readonly onPipelineEvent: (event: PipelineEvent) => void;
  readonly persistentCacheServices: PersistentCacheServices | null;
  readonly settings: Pick<VulnDashSettings, 'cacheStorage' | 'feeds' | 'sourceSyncCursor' | 'syncControls'>;
}

export interface VulnDashAppModuleOptions {
  readonly getActiveWorkspacePurls: () => Promise<readonly string[]>;
  readonly getSboms: () => readonly ImportedSbomConfig[];
  readonly metadataCache: VulnDashMetadataCacheFacade;
  readonly normalizePath?: (path: string) => string;
  readonly storageScheduler?: CooperativeScheduler;
  readonly updateSbomConfig: (sbomId: string, updates: Partial<ImportedSbomConfig>) => Promise<void>;
  readonly vault: VulnDashVaultFacade;
  readonly createHttpClient?: () => IHttpClient;
}

interface VulnDashProjectNoteLookup {
  getByPaths(references: Parameters<ProjectNoteLookupService['getByPaths']>[0]): ReturnType<ProjectNoteLookupService['getByPaths']>;
  listProjectNotes(): ProjectNoteOption[];
  resolveByPath(notePath: string, displayName?: string): Promise<ProjectNoteLookupResult>;
}

export class VulnDashAppModule {
  public readonly alertEngine = new AlertEngine();
  public readonly componentInventoryService = new ComponentInventoryService();
  public readonly componentPreferenceService = new ComponentPreferenceService();
  public readonly componentVulnerabilityLinkService = new ComponentVulnerabilityLinkService();
  public readonly dailyRollupGenerator: DailyRollupGenerator;
  public readonly projectNoteLookup: VulnDashProjectNoteLookup;
  public readonly relationshipNormalizer = new RelationshipNormalizer();
  public readonly resolveAffectedProjects: ResolveAffectedProjects;
  public readonly sbomCatalogService = new SbomCatalogService();
  public readonly sbomComparisonService = new SbomComparisonService();
  public readonly sbomComponentIndex = new SbomComponentIndex();
  public readonly sbomFilterMergeService = new SbomFilterMergeService();
  public readonly sbomImportService: SbomImportService;
  public readonly sbomProjectMappingRepository: SbomProjectMappingRepository;
  public readonly settingsMigrator = new SettingsMigrator();
  private readonly createHttpClient: () => IHttpClient;
  private readonly getActiveWorkspacePurls: () => Promise<readonly string[]>;
  private readonly storageScheduler: CooperativeScheduler;

  private constructor(
    options: Pick<VulnDashAppModuleOptions, 'createHttpClient' | 'getActiveWorkspacePurls' | 'storageScheduler'>,
    services: {
      readonly dailyRollupGenerator: DailyRollupGenerator;
      readonly projectNoteLookup: VulnDashProjectNoteLookup;
      readonly sbomImportService: SbomImportService;
      readonly sbomProjectMappingRepository: SbomProjectMappingRepository;
    }
  ) {
    this.dailyRollupGenerator = services.dailyRollupGenerator;
    this.projectNoteLookup = services.projectNoteLookup;
    this.sbomImportService = services.sbomImportService;
    this.sbomProjectMappingRepository = services.sbomProjectMappingRepository;
    this.resolveAffectedProjects = new ResolveAffectedProjects(
      this.sbomProjectMappingRepository,
      {
        getByPaths: async (references) => this.projectNoteLookup.getByPaths(references)
      }
    );
    this.createHttpClient = options.createHttpClient ?? (() => new HttpClient());
    this.getActiveWorkspacePurls = options.getActiveWorkspacePurls;
    this.storageScheduler = options.storageScheduler ?? new CooperativeScheduler();
  }

  public static create(options: VulnDashAppModuleOptions): VulnDashAppModule {
    const normalizePath = options.normalizePath ?? ((path: string) => path);
    const projectNoteLookup = new ProjectNoteLookupService(options.vault);
    const notePathResolverFactory = new ComponentNoteResolverFactory(
      options.vault as never,
      options.metadataCache as never
    ) as SbomComponentNotePathResolverFactory;
    const sbomImportService = new SbomImportService(
      options.vault.adapter,
      undefined,
      notePathResolverFactory
    );
    const dailyRollupGenerator = new DailyRollupGenerator(
      new SelectRollupFindings(),
      new RollupMarkdownRenderer(),
      new DailyRollupNoteWriter({
        create: async (path, noteContent) => {
          await options.vault.create(normalizePath(path), noteContent);
        },
        createFolder: async (path) => {
          await options.vault.createFolder(normalizePath(path));
        },
        exists: async (path) => options.vault.adapter.exists(normalizePath(path)),
        read: async (path) => options.vault.adapter.read(normalizePath(path)),
        write: async (path, noteContent) => {
          await options.vault.adapter.write(normalizePath(path), noteContent);
        }
      })
    );
    const sbomProjectMappingRepository = new SbomProjectMappingRepository(
      options.getSboms,
      options.updateSbomConfig
    );

    return new VulnDashAppModule(options, {
      dailyRollupGenerator,
      projectNoteLookup,
      sbomImportService,
      sbomProjectMappingRepository
    });
  }

  public createSyncService(options: CreateSyncServiceOptions): VulnerabilitySyncService {
    const client = this.createHttpClient();
    const osvQueryCache: IOsvQueryCache | undefined = options.persistentCacheServices?.cacheRepository;
    const feeds = buildFeedsFromConfig(options.settings.feeds, client, options.settings.syncControls, {
      ...(osvQueryCache ? { osvQueryCache } : {}),
      getPurls: this.getActiveWorkspacePurls
    });

    return new VulnerabilitySyncService({
      controls: options.settings.syncControls,
      feeds,
      ...(options.persistentCacheServices ? {
        persistence: {
          cacheHydrationLimit: options.settings.cacheStorage.hydrateMaxItems,
          cacheHydrationPageSize: options.settings.cacheStorage.hydratePageSize,
          cacheStore: options.persistentCacheServices.cacheRepository,
          metadataStore: options.persistentCacheServices.metadataRepository
        }
      } : {}),
      onPipelineEvent: options.onPipelineEvent,
      state: {
        cache: [...options.cachedVulnerabilities],
        sourceSyncCursor: options.settings.sourceSyncCursor
      }
    });
  }

  public async initializePersistentCache(
    loadedPluginData: SettingsMigrationInput | null,
    settings: Pick<VulnDashSettings, 'cacheStorage' | 'feeds'>
  ): Promise<PersistentCacheInitializationResult> {
    try {
      const cacheDb = new VulnCacheDb();
      await cacheDb.open();
      const cacheRepository = new VulnCacheRepository(cacheDb);
      const metadataRepository = new SyncMetadataRepository(cacheDb);
      const triageRepository = new IndexedDbTriageRepository(cacheDb);
      const cacheHydrator = new CacheHydrator(cacheRepository, this.storageScheduler);
      const cachePruner = new CachePruner(
        cacheRepository,
        this.storageScheduler,
        this.getActiveWorkspacePurls
      );
      const persistentCacheServices: PersistentCacheServices = {
        cacheDb,
        cacheHydrator,
        cachePruner,
        cacheRepository,
        metadataRepository,
        triageRepository
      };
      const triageJoinUseCase = new JoinTriageState(triageRepository);
      const triageSetUseCase = new SetTriageState(triageRepository);
      const migration = await new LegacyDataMigration(cacheRepository, metadataRepository).migrate(
        loadedPluginData,
        settings.feeds
      );
      const hydrated = await cacheHydrator.hydrateLatest({
        limit: settings.cacheStorage.hydrateMaxItems,
        pageSize: settings.cacheStorage.hydratePageSize
      });

      cachePruner.schedule(settings.cacheStorage);

      return {
        cachedVulnerabilities: hydrated,
        lastFetchAt: hydrated.length > 0 ? Date.now() : 0,
        persistentCacheServices,
        removedLegacyFields: migration.removedLegacyFields,
        triageJoinUseCase,
        triageSetUseCase
      };
    } catch (error) {
      console.warn('[vulndash.cache.persistence_unavailable]', error);
      return {
        cachedVulnerabilities: [],
        lastFetchAt: 0,
        persistentCacheServices: null,
        removedLegacyFields: false,
        triageJoinUseCase: null,
        triageSetUseCase: null
      };
    }
  }

  public invalidateMarkdownNotePathCaches(): void {
    this.sbomImportService.invalidateAllCaches();
  }

  public invalidateSbomCache(sbomId: string): void {
    this.sbomImportService.invalidateCache(sbomId);
  }

  public listProjectNotes(): ProjectNoteOption[] {
    return this.projectNoteLookup.listProjectNotes();
  }

  public async resolveProjectNotePath(notePath: string, displayName?: string): Promise<ProjectNoteLookupResult> {
    return this.projectNoteLookup.resolveByPath(notePath, displayName);
  }

  public async closePersistentCache(persistentCacheServices: PersistentCacheServices | null): Promise<void> {
    if (!persistentCacheServices) {
      return;
    }

    await persistentCacheServices.cacheDb.close();
  }
}
