import assert from 'node:assert/strict';
import test from 'node:test';
import { SbomCatalogService } from '../../../src/application/sbom/SbomCatalogService';
import type {
  NormalizedComponent,
  NormalizedSbomDocument
} from '../../../src/domain/sbom/types';

const service = new SbomCatalogService();

const createComponent = (overrides: Partial<NormalizedComponent> = {}): NormalizedComponent => ({
  cweGroups: [],
  dataview: {
    cweList: [],
    severities: [],
    vulnerabilityCount: 0,
    vulnerabilityIds: []
  },
  id: 'component-1',
  name: 'component',
  vulnerabilities: [],
  vulnerabilityCount: 0,
  ...overrides
});

const createDocument = (
  sourcePath: string,
  format: 'cyclonedx' | 'spdx',
  components: NormalizedComponent[]
): NormalizedSbomDocument => ({
  components,
  format,
  name: sourcePath.split('/').at(-1) ?? sourcePath,
  sourcePath
});

test('builds one merged catalog across CycloneDX and SPDX sources using stable keys', () => {
  const catalog = service.buildCatalog([
    createDocument('reports/beta.spdx.json', 'spdx', [
      createComponent({
        cpe: 'cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*',
        id: 'SPDXRef-Package-lodash',
        name: 'lodash',
        purl: 'pkg:npm/lodash@4.17.21',
        version: '4.17.21'
      }),
      createComponent({
        cpe: 'cpe:2.3:a:react:react:18.3.1:*:*:*:*:*:*:*',
        id: 'SPDXRef-Package-react',
        name: 'react',
        version: '18.3.1'
      })
    ]),
    createDocument('reports/alpha.cdx.json', 'cyclonedx', [
      createComponent({
        highestSeverity: 'high',
        id: 'bom-ref-lodash',
        name: 'lodash',
        purl: 'pkg:npm/lodash@4.17.21',
        version: '4.17.21',
        vulnerabilities: [
          {
            cwes: [79],
            id: 'CVE-2026-0001',
            score: 7.5,
            severity: 'high'
          }
        ],
        vulnerabilityCount: 1
      }),
      createComponent({
        cpe: 'cpe:2.3:a:react:react:18.3.1:*:*:*:*:*:*:*',
        id: 'bom-ref-react',
        name: 'react',
        version: '18.3.1'
      })
    ]),
    createDocument('reports/gamma.cdx.json', 'cyclonedx', [
      createComponent({
        id: 'bom-ref-express',
        name: 'express',
        version: '4.19.2'
      })
    ])
  ]);

  assert.equal(catalog.componentCount, 3);
  assert.deepEqual(catalog.formats, ['cyclonedx', 'spdx']);
  assert.deepEqual(catalog.sourceFiles, [
    'reports/alpha.cdx.json',
    'reports/beta.spdx.json',
    'reports/gamma.cdx.json'
  ]);
  assert.deepEqual(
    catalog.components.map((component) => component.key),
    [
      'purl:pkg:npm/lodash@4.17.21',
      'name-version:express@4.19.2',
      'cpe:cpe:2.3:a:react:react:18.3.1:*:*:*:*:*:*:*'
    ]
  );
  assert.equal(catalog.components[0]?.sourceFiles.length, 2);
  assert.equal(catalog.components[0]?.vulnerabilityCount, 1);
});

test('uses cpe and normalized name/version fallback identities deterministically', () => {
  const catalog = service.buildCatalog([
    createDocument('reports/zeta.cdx.json', 'cyclonedx', [
      createComponent({
        cpe: 'CPE:2.3:A:EXAMPLE:SHARED:1.0.0:*:*:*:*:*:*:*',
        id: 'component-a',
        name: 'shared',
        version: '1.0.0'
      }),
      createComponent({
        id: 'component-b',
        name: 'platform-api',
        version: '2.5.0'
      })
    ]),
    createDocument('reports/eta.spdx.json', 'spdx', [
      createComponent({
        cpe: 'cpe:2.3:a:example:shared:1.0.0:*:*:*:*:*:*:*',
        id: 'component-c',
        name: 'Shared',
        version: '1.0.0'
      }),
      createComponent({
        id: 'component-d',
        name: ' Platform-API ',
        version: ' 2.5.0 '
      })
    ])
  ]);

  assert.equal(catalog.componentCount, 2);
  assert.deepEqual(
    catalog.components.map((component) => component.key).sort((left, right) => left.localeCompare(right)),
    [
      'cpe:cpe:2.3:a:example:shared:1.0.0:*:*:*:*:*:*:*',
      'name-version:platform-api@2.5.0'
    ]
  );
});

test('orders catalog output deterministically by severity and then name/version', () => {
  const catalog = service.buildCatalog([
    createDocument('reports/omega.cdx.json', 'cyclonedx', [
      createComponent({
        highestSeverity: 'medium',
        id: 'component-medium',
        name: 'zebra',
        vulnerabilities: [
          {
            cwes: [],
            id: 'CVE-2026-0003',
            severity: 'medium'
          }
        ],
        vulnerabilityCount: 1
      }),
      createComponent({
        id: 'component-none',
        name: 'alpha'
      }),
      createComponent({
        highestSeverity: 'critical',
        id: 'component-critical',
        name: 'beta',
        vulnerabilities: [
          {
            cwes: [],
            id: 'CVE-2026-0004',
            severity: 'critical'
          }
        ],
        vulnerabilityCount: 1
      })
    ])
  ]);

  assert.deepEqual(
    catalog.components.map((component) => component.name),
    ['beta', 'zebra', 'alpha']
  );
});
