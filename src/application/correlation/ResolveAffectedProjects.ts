import type { ComponentRelationshipGraph } from '../sbom/types';
import { RelationshipNormalizer } from '../sbom/RelationshipNormalizer';
import type { Vulnerability } from '../../domain/entities/Vulnerability';
import type { ProjectNoteReference } from '../../domain/correlation/ProjectNoteReference';
import type { SbomProjectMappingRepository } from '../../domain/correlation/SbomProjectMappingRepository';
import {
  EMPTY_AFFECTED_PROJECT_RESOLUTION,
  type AffectedProjectResolution,
  type ResolvedAffectedProject,
  type ResolvedAffectedProjectStatus,
  type UnmappedAffectedSbom
} from '../../domain/correlation/AffectedProjectResolution';

export interface AffectedProjectComponentIndex {
  getSbomIdsForComponent(componentKey: string): readonly string[];
}

export interface ProjectNoteLookupResult {
  readonly displayName: string;
  readonly notePath: string;
  readonly status: ResolvedAffectedProjectStatus;
}

export interface ProjectNoteLookup {
  getByPaths(references: readonly ProjectNoteReference[]): Promise<Map<string, ProjectNoteLookupResult>>;
}

export interface ResolveAffectedProjectsSbom {
  readonly id: string;
  readonly label: string;
}

interface AggregatedResolvedProject {
  readonly displayName: string;
  readonly notePath: string;
  readonly sourceSbomIds: Set<string>;
  readonly sourceSbomLabels: Set<string>;
  readonly status: ResolvedAffectedProjectStatus;
}

const compareAffectedProjects = (
  left: ResolvedAffectedProject,
  right: ResolvedAffectedProject
): number =>
  left.status.localeCompare(right.status)
  || left.displayName.localeCompare(right.displayName)
  || left.notePath.localeCompare(right.notePath);

const compareUnmappedSboms = (
  left: UnmappedAffectedSbom,
  right: UnmappedAffectedSbom
): number =>
  left.sbomLabel.localeCompare(right.sbomLabel)
  || left.sbomId.localeCompare(right.sbomId);

export class ResolveAffectedProjects {
  public constructor(
    private readonly mappingRepository: SbomProjectMappingRepository,
    private readonly projectNoteLookup: ProjectNoteLookup,
    private readonly relationshipNormalizer = new RelationshipNormalizer()
  ) {}

  public async execute(input: {
    componentIndex: AffectedProjectComponentIndex;
    relationships: ComponentRelationshipGraph;
    sboms: readonly ResolveAffectedProjectsSbom[];
    vulnerabilities: readonly Vulnerability[];
  }): Promise<Map<string, AffectedProjectResolution>> {
    if (input.vulnerabilities.length === 0) {
      return new Map();
    }

    const mappings = await this.mappingRepository.list();
    const mappingsBySbomId = new Map(mappings.map((mapping) => [mapping.sbomId, mapping.projectNote] as const));
    const noteStates = await this.projectNoteLookup.getByPaths(mappings.map((mapping) => mapping.projectNote));
    const sbomsById = new Map(input.sboms.map((sbom) => [sbom.id, sbom] as const));
    const results = new Map<string, AffectedProjectResolution>();

    for (const vulnerability of input.vulnerabilities) {
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
      const relatedComponents = input.relationships.componentsByVulnerability.get(vulnerabilityRef) ?? [];
      if (relatedComponents.length === 0) {
        results.set(vulnerabilityRef, EMPTY_AFFECTED_PROJECT_RESOLUTION);
        continue;
      }

      const matchedSbomIds = new Set<string>();
      for (const component of relatedComponents) {
        for (const sbomId of input.componentIndex.getSbomIdsForComponent(component.key)) {
          matchedSbomIds.add(sbomId);
        }
      }

      if (matchedSbomIds.size === 0) {
        results.set(vulnerabilityRef, EMPTY_AFFECTED_PROJECT_RESOLUTION);
        continue;
      }

      const aggregatedProjects = new Map<string, AggregatedResolvedProject>();
      const unmappedSboms = new Map<string, UnmappedAffectedSbom>();

      for (const sbomId of matchedSbomIds) {
        const sbom = sbomsById.get(sbomId);
        if (!sbom) {
          continue;
        }

        const mapping = mappingsBySbomId.get(sbomId);
        if (!mapping) {
          unmappedSboms.set(sbomId, {
            sbomId,
            sbomLabel: sbom.label
          });
          continue;
        }

        const noteState = noteStates.get(mapping.notePath) ?? {
          displayName: mapping.displayName ?? sbom.label,
          notePath: mapping.notePath,
          status: 'broken'
        } satisfies ProjectNoteLookupResult;
        const existing = aggregatedProjects.get(noteState.notePath);
        if (existing) {
          existing.sourceSbomIds.add(sbom.id);
          existing.sourceSbomLabels.add(sbom.label);
          continue;
        }

        aggregatedProjects.set(noteState.notePath, {
          displayName: noteState.displayName,
          notePath: noteState.notePath,
          sourceSbomIds: new Set([sbom.id]),
          sourceSbomLabels: new Set([sbom.label]),
          status: noteState.status
        });
      }

      results.set(vulnerabilityRef, {
        affectedProjects: Array.from(aggregatedProjects.values())
          .map((project) => ({
            displayName: project.displayName,
            notePath: project.notePath,
            sourceSbomIds: Array.from(project.sourceSbomIds).sort((left, right) => left.localeCompare(right)),
            sourceSbomLabels: Array.from(project.sourceSbomLabels).sort((left, right) => left.localeCompare(right)),
            status: project.status
          }))
          .sort(compareAffectedProjects),
        unmappedSboms: Array.from(unmappedSboms.values()).sort(compareUnmappedSboms)
      });
    }

    return results;
  }
}
