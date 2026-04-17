import assert from 'node:assert/strict';
import test from 'node:test';
import { createProjectNoteReference, normalizeProjectNotePath } from '../../../src/domain/correlation/ProjectNoteReference';
import { createSbomProjectMapping } from '../../../src/domain/correlation/SbomProjectMapping';

test('project note references normalize vault paths and trim display names', () => {
  const reference = createProjectNoteReference('.\\Projects\\Portal.md', '  Portal Platform  ');

  assert.equal(normalizeProjectNotePath('.\\Projects\\Portal.md'), 'Projects/Portal.md');
  assert.deepEqual(reference, {
    displayName: 'Portal Platform',
    notePath: 'Projects/Portal.md'
  });
});

test('sbom project mappings require a non-empty sbom identifier', () => {
  assert.throws(() => createSbomProjectMapping('   ', createProjectNoteReference('Projects/Portal.md')));
});
