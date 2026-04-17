import type { ImportedSbomConfig } from '../../application/use-cases/types';
import {
  createProjectNoteReference,
  normalizeProjectNotePath,
  type ProjectNoteReference
} from '../../domain/correlation/ProjectNoteReference';
import {
  createSbomProjectMapping,
  type SbomProjectMapping
} from '../../domain/correlation/SbomProjectMapping';
import type { SbomProjectMappingRepository as SbomProjectMappingRepositoryPort } from '../../domain/correlation/SbomProjectMappingRepository';

type SbomConfigUpdate = Pick<ImportedSbomConfig, 'linkedProjectDisplayName' | 'linkedProjectNotePath'>;

export class SbomProjectMappingRepository implements SbomProjectMappingRepositoryPort {
  public constructor(
    private readonly getSboms: () => readonly ImportedSbomConfig[],
    private readonly updateSbomConfig: (sbomId: string, updates: Partial<SbomConfigUpdate>) => Promise<void>
  ) {}

  public async deleteBySbomId(sbomId: string): Promise<void> {
    await this.updateSbomConfig(sbomId, {
      linkedProjectDisplayName: '',
      linkedProjectNotePath: ''
    });
  }

  public async getBySbomId(sbomId: string): Promise<SbomProjectMapping | null> {
    const sbom = this.getSboms().find((entry) => entry.id === sbomId);
    if (!sbom || !sbom.linkedProjectNotePath) {
      return null;
    }

    return createSbomProjectMapping(
      sbom.id,
      createProjectNoteReference(sbom.linkedProjectNotePath, sbom.linkedProjectDisplayName)
    );
  }

  public async list(): Promise<SbomProjectMapping[]> {
    return this.getSboms().flatMap((sbom) => {
      if (!sbom.linkedProjectNotePath) {
        return [];
      }

      return [createSbomProjectMapping(
        sbom.id,
        createProjectNoteReference(sbom.linkedProjectNotePath, sbom.linkedProjectDisplayName)
      )];
    });
  }

  public async replaceNotePath(oldNotePath: string, nextProjectNote: ProjectNoteReference): Promise<number> {
    const normalizedOldPath = normalizeProjectNotePath(oldNotePath);
    const matchingSboms = this.getSboms().filter((sbom) =>
      normalizeProjectNotePath(sbom.linkedProjectNotePath ?? '') === normalizedOldPath);

    for (const sbom of matchingSboms) {
      await this.save(createSbomProjectMapping(sbom.id, nextProjectNote));
    }

    return matchingSboms.length;
  }

  public async save(mapping: SbomProjectMapping): Promise<void> {
    await this.updateSbomConfig(mapping.sbomId, {
      linkedProjectDisplayName: mapping.projectNote.displayName ?? '',
      linkedProjectNotePath: mapping.projectNote.notePath
    });
  }
}
