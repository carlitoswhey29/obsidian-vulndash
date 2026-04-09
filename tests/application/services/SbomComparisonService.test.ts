import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomComparisonService } from '../../../src/application/services/SbomComparisonService';
import type { ImportedSbomConfig } from '../../../src/application/services/types';

const comparisonService = new SbomComparisonService();

const createSbom = (id: string, components: ImportedSbomConfig['components']): ImportedSbomConfig => ({
  id,
  label: id,
  path: `${id}.json`,
  namespace: '',
  enabled: true,
  components,
  lastImportedAt: null,
  lastImportHash: null,
  lastImportError: null
});

test('compares SBOM component groups and identifies left-only, right-only, and changed entries', () => {
  const left = createSbom('left', [
    {
      id: 'component-1',
      name: 'platform-api',
      normalizedName: 'Platform Api',
      version: '1.0.0',
      purl: 'pkg:npm/%40acme/platform-api@1.0.0',
      cpe: '',
      bomRef: '',
      namespace: '@acme',
      enabled: true,
      excluded: false
    },
    {
      id: 'component-2',
      name: 'portal-web',
      normalizedName: 'Portal Web',
      version: '2.0.0',
      purl: '',
      cpe: '',
      bomRef: '',
      namespace: '',
      enabled: true,
      excluded: false
    }
  ]);
  const right = createSbom('right', [
    {
      id: 'component-3',
      name: 'platform-api',
      normalizedName: 'Platform Api',
      version: '1.1.0',
      purl: 'pkg:npm/%40acme/platform-api@1.1.0',
      cpe: '',
      bomRef: '',
      namespace: '@acme',
      enabled: true,
      excluded: false
    },
    {
      id: 'component-4',
      name: 'gateway-service',
      normalizedName: 'Gateway Service',
      version: '3.0.0',
      purl: '',
      cpe: '',
      bomRef: '',
      namespace: '',
      enabled: true,
      excluded: false
    }
  ]);

  const result = comparisonService.compare(left, right);

  assert.equal(result.changed.length, 1);
  assert.equal(result.changed[0]?.label, '@acme / Platform Api');
  assert.equal(result.changed[0]?.fields.includes('versions'), true);
  assert.equal(result.leftOnly.length, 1);
  assert.equal(result.leftOnly[0]?.label, 'Portal Web');
  assert.equal(result.rightOnly.length, 1);
  assert.equal(result.rightOnly[0]?.label, 'Gateway Service');
  assert.equal(result.unchangedCount, 0);
});

test('counts unchanged groups when grouped signatures match', () => {
  const left = createSbom('left', [{
    id: 'component-1',
    name: 'platform-api',
    normalizedName: 'Platform Api',
    version: '1.0.0',
    purl: '',
    cpe: '',
    bomRef: '',
    namespace: '',
    enabled: true,
    excluded: false
  }]);
  const right = createSbom('right', [{
    id: 'component-2',
    name: 'platform-api',
    normalizedName: 'Platform Api',
    version: '1.0.0',
    purl: '',
    cpe: '',
    bomRef: '',
    namespace: '',
    enabled: true,
    excluded: false
  }]);

  const result = comparisonService.compare(left, right);
  assert.equal(result.changed.length, 0);
  assert.equal(result.leftOnly.length, 0);
  assert.equal(result.rightOnly.length, 0);
  assert.equal(result.unchangedCount, 1);
});
