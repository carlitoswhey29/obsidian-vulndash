import assert from 'node:assert/strict';
import test from 'node:test';
import { clearSbomProjectNoteMapping, saveSbomProjectNoteMapping } from '../../../src/presentation/modals/SbomManagerModal';

test('saveSbomProjectNoteMapping forwards the sbom id and note path to plugin wiring', async () => {
  const calls: Array<{ notePath: string; sbomId: string; }> = [];
  await saveSbomProjectNoteMapping({
    linkSbomToProjectNote: async (sbomId, notePath) => {
      calls.push({ notePath, sbomId });
    }
  }, 'sbom-1', 'Projects/Portal.md');

  assert.deepEqual(calls, [{ notePath: 'Projects/Portal.md', sbomId: 'sbom-1' }]);
});

test('clearSbomProjectNoteMapping forwards the sbom id to plugin wiring', async () => {
  const calls: string[] = [];
  await clearSbomProjectNoteMapping({
    clearSbomProjectNote: async (sbomId) => {
      calls.push(sbomId);
    }
  }, 'sbom-2');

  assert.deepEqual(calls, ['sbom-2']);
});
