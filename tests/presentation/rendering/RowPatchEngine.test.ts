import assert from 'node:assert/strict';
import test from 'node:test';
import { buildRowPatchPlan } from '../../../src/presentation/rendering/RowPatchEngine';
import { RowRegistry } from '../../../src/presentation/rendering/RowRegistry';

test('buildRowPatchPlan creates, patches, and removes only the affected keys', () => {
  const plan = buildRowPatchPlan({
    currentKeys: ['nvd:CVE-1', 'nvd:CVE-2'],
    dirtyKeys: new Set(['nvd:CVE-2']),
    nextKeys: ['nvd:CVE-2', 'nvd:CVE-3']
  });

  assert.deepEqual(plan, {
    createKeys: ['nvd:CVE-3'],
    patchKeys: ['nvd:CVE-2'],
    removeKeys: ['nvd:CVE-1']
  });
});

test('buildRowPatchPlan leaves stable visible rows untouched when no dirty keys are present', () => {
  const plan = buildRowPatchPlan({
    currentKeys: ['nvd:CVE-1', 'nvd:CVE-2'],
    nextKeys: ['nvd:CVE-1', 'nvd:CVE-2']
  });

  assert.deepEqual(plan, {
    createKeys: [],
    patchKeys: [],
    removeKeys: []
  });
});

test('buildRowPatchPlan can force patch all mounted visible rows for structural view changes', () => {
  const plan = buildRowPatchPlan({
    currentKeys: ['nvd:CVE-1', 'nvd:CVE-2'],
    forcePatchAll: true,
    nextKeys: ['nvd:CVE-1', 'nvd:CVE-2']
  });

  assert.deepEqual(plan, {
    createKeys: [],
    patchKeys: ['nvd:CVE-1', 'nvd:CVE-2'],
    removeKeys: []
  });
});

test('row registry stores and removes mounted rows by stable key', () => {
  const registry = new RowRegistry<number>();
  registry.set('nvd:CVE-1', 1);
  registry.set('nvd:CVE-2', 2);

  assert.equal(registry.get('nvd:CVE-1'), 1);
  assert.deepEqual(registry.keys(), ['nvd:CVE-1', 'nvd:CVE-2']);

  registry.delete('nvd:CVE-1');

  assert.equal(registry.has('nvd:CVE-1'), false);
  assert.deepEqual(registry.keys(), ['nvd:CVE-2']);
});
