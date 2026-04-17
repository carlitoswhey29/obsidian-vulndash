import assert from 'node:assert/strict';
import test from 'node:test';
import { ComponentPreferenceService } from '../../../src/application/sbom/ComponentPreferenceService';
import type { ComponentCatalog } from '../../../src/application/sbom/types';
import type { VulnDashSettings } from '../../../src/application/use-cases/types';

const service = new ComponentPreferenceService();

const createSettings = (
  overrides: Partial<Pick<VulnDashSettings, 'disabledSbomComponentKeys' | 'followedSbomComponentKeys'>> = {}
): Pick<VulnDashSettings, 'disabledSbomComponentKeys' | 'followedSbomComponentKeys'> => ({
  disabledSbomComponentKeys: [],
  followedSbomComponentKeys: [],
  ...overrides
});

const createCatalog = (): ComponentCatalog => ({
  componentCount: 2,
  components: [
    {
      cweGroups: [],
      formats: ['cyclonedx'],
      isEnabled: true,
      isFollowed: false,
      key: 'purl:pkg:npm/lodash@4.17.21',
      name: 'lodash',
      sourceFiles: ['reports/a.json'],
      sources: [],
      vulnerabilities: [],
      vulnerabilityCount: 0
    },
    {
      cweGroups: [],
      formats: ['cyclonedx'],
      isEnabled: true,
      isFollowed: false,
      key: 'name-version:react@18.3.1',
      name: 'react',
      sourceFiles: ['reports/a.json'],
      sources: [],
      vulnerabilities: [],
      vulnerabilityCount: 0
    }
  ],
  formats: ['cyclonedx'],
  sourceFiles: ['reports/a.json']
});

test('defaults to not followed and enabled', () => {
  const settings = createSettings();

  assert.equal(service.isFollowed('purl:pkg:npm/lodash@4.17.21', settings), false);
  assert.equal(service.isEnabled('purl:pkg:npm/lodash@4.17.21', settings), true);
});

test('follow persists a normalized key only once and unfollow removes it', () => {
  const followed = service.follow(' PURL:PKG:NPM/LODASH@4.17.21 ', createSettings({
    followedSbomComponentKeys: ['purl:pkg:npm/lodash@4.17.21']
  }));

  assert.deepEqual(followed.followedSbomComponentKeys, ['purl:pkg:npm/lodash@4.17.21']);

  const unfollowed = service.unfollow('purl:pkg:npm/lodash@4.17.21', followed);
  assert.deepEqual(unfollowed.followedSbomComponentKeys, []);
});

test('disable and enable remain independent from followed state', () => {
  const disabled = service.disable('name-version:react@18.3.1', createSettings({
    followedSbomComponentKeys: ['name-version:react@18.3.1']
  }));

  assert.deepEqual(disabled.followedSbomComponentKeys, ['name-version:react@18.3.1']);
  assert.deepEqual(disabled.disabledSbomComponentKeys, ['name-version:react@18.3.1']);
  assert.equal(service.isFollowed('name-version:react@18.3.1', disabled), true);
  assert.equal(service.isEnabled('name-version:react@18.3.1', disabled), false);

  const enabled = service.enable('name-version:react@18.3.1', disabled);
  assert.deepEqual(enabled.followedSbomComponentKeys, ['name-version:react@18.3.1']);
  assert.deepEqual(enabled.disabledSbomComponentKeys, []);
});

test('applyPreferences overlays component state onto a catalog', () => {
  const catalog = service.applyPreferences(createCatalog(), createSettings({
    disabledSbomComponentKeys: ['name-version:react@18.3.1'],
    followedSbomComponentKeys: ['purl:pkg:npm/lodash@4.17.21']
  }));

  assert.equal(catalog.components[0]?.isFollowed, true);
  assert.equal(catalog.components[0]?.isEnabled, true);
  assert.equal(catalog.components[1]?.isFollowed, false);
  assert.equal(catalog.components[1]?.isEnabled, false);
});

test('malformed persisted values normalize safely', () => {
  const normalized = service.normalizeSettings(createSettings({
    disabledSbomComponentKeys: [' name-version:react@18.3.1 ', 5, null] as unknown as string[],
    followedSbomComponentKeys: 'invalid' as unknown as string[]
  }));

  assert.deepEqual(normalized.disabledSbomComponentKeys, ['name-version:react@18.3.1']);
  assert.deepEqual(normalized.followedSbomComponentKeys, []);
});
