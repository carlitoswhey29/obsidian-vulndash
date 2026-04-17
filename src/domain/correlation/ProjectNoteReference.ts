const normalizeProjectNotePathValue = (value: string): string =>
  value.trim().replace(/\\/g, '/').replace(/\/+/g, '/').replace(/^\.?\//, '');

export interface ProjectNoteReference {
  readonly displayName?: string;
  readonly notePath: string;
}

export const normalizeProjectNotePath = (value: string): string =>
  normalizeProjectNotePathValue(value);

export const createProjectNoteReference = (
  notePath: string,
  displayName?: string
): ProjectNoteReference => {
  const normalizedPath = normalizeProjectNotePathValue(notePath);
  if (!normalizedPath) {
    throw new Error('Project note path is required.');
  }

  const normalizedDisplayName = displayName?.trim();
  if (!normalizedDisplayName) {
    return {
      notePath: normalizedPath
    };
  }

  return {
    displayName: normalizedDisplayName,
    notePath: normalizedPath
  };
};
