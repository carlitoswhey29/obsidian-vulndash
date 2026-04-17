import type { ProjectNoteReference } from './ProjectNoteReference';

export interface SbomProjectMapping {
  readonly projectNote: ProjectNoteReference;
  readonly sbomId: string;
}

export const createSbomProjectMapping = (
  sbomId: string,
  projectNote: ProjectNoteReference
): SbomProjectMapping => {
  const normalizedSbomId = sbomId.trim();
  if (!normalizedSbomId) {
    throw new Error('SBOM identifier is required.');
  }

  return {
    projectNote,
    sbomId: normalizedSbomId
  };
};
