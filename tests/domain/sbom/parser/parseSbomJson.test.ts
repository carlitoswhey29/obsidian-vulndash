import assert from 'node:assert/strict';
import test from 'node:test';
import { parseSbomJson } from '../../../../src/domain/sbom/parser';

const createSource = (path: string) => ({
  basename: path.split('/').at(-1)?.replace(/\.[^.]+$/, '') ?? 'sbom',
  path
});

test('parses CycloneDX components, vulnerability associations, severities, and CWE groups', () => {
  const document = parseSbomJson({
    bomFormat: 'CycloneDX',
    metadata: {
      component: {
        name: 'Demo Platform'
      }
    },
    components: [
      {
        'bom-ref': 'pkg:npm/lodash@4.17.21',
        licenses: [{ license: { id: 'MIT' } }],
        name: 'lodash',
        purl: 'pkg:npm/lodash@4.17.21',
        supplier: { name: 'OpenJS' },
        version: '4.17.21'
      },
      {
        'bom-ref': 'pkg:npm/react@18.3.1',
        name: 'react'
      }
    ],
    vulnerabilities: [
      {
        affects: [{ ref: 'pkg:npm/lodash@4.17.21' }],
        cwes: [79, 89],
        description: 'Primary vulnerability',
        id: 'CVE-2026-0001',
        ratings: [{ score: 9.8, severity: 'CRITICAL' }]
      },
      {
        affects: [
          { ref: 'pkg:npm/lodash@4.17.21' },
          { ref: 'pkg:npm/lodash@4.17.21' }
        ],
        cwes: [79],
        id: 'CVE-2026-0002',
        ratings: [{ score: 5.1, severity: 'medium' }]
      }
    ]
  }, {
    source: createSource('reports/demo.cdx.json')
  });

  assert.equal(document.format, 'cyclonedx');
  assert.equal(document.name, 'Demo Platform');
  assert.equal(document.components.length, 3);

  const lodash = document.components.find((component) => component.name === 'lodash');
  assert.ok(lodash);
  assert.equal(lodash.license, 'MIT');
  assert.equal(lodash.supplier, 'OpenJS');
  assert.equal(lodash.vulnerabilityCount, 2);
  assert.equal(lodash.highestSeverity, 'critical');
  assert.deepEqual(lodash.dataview.cweList, ['CWE-79', 'CWE-89']);
  assert.deepEqual(lodash.dataview.severities, ['critical', 'medium']);
  assert.deepEqual(lodash.cweGroups, [
    {
      count: 2,
      cwe: 79,
      vulnerabilityIds: ['CVE-2026-0001', 'CVE-2026-0002']
    },
    {
      count: 1,
      cwe: 89,
      vulnerabilityIds: ['CVE-2026-0001']
    }
  ]);
  assert.deepEqual(
    lodash.vulnerabilities.map((vulnerability) => vulnerability.id),
    ['CVE-2026-0001', 'CVE-2026-0002']
  );
});

test('parses CycloneDX documents with missing optional fields without crashing', () => {
  const document = parseSbomJson({
    bomFormat: 'CycloneDX',
    components: [
      {
        'bom-ref': 'component-1'
      }
    ]
  }, {
    source: createSource('reports/partial.cdx.json')
  });

  assert.equal(document.components.length, 1);
  assert.equal(document.components[0]?.name, 'Unnamed component 1');
  assert.equal(document.components[0]?.vulnerabilityCount, 0);
  assert.deepEqual(document.components[0]?.dataview.cweList, []);
});

test('parses SPDX package metadata including purl and cpe external references', () => {
  const document = parseSbomJson({
    SPDXID: 'SPDXRef-DOCUMENT',
    name: 'Demo SPDX Document',
    packages: [
      {
        SPDXID: 'SPDXRef-Package-lodash',
        externalRefs: [
          {
            referenceLocator: 'pkg:npm/lodash@4.17.21',
            referenceType: 'purl'
          },
          {
            referenceLocator: 'cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*',
            referenceType: 'cpe23Type'
          }
        ],
        licenseDeclared: 'MIT',
        name: 'lodash',
        supplier: 'Organization: OpenJS',
        versionInfo: '4.17.21'
      }
    ],
    spdxVersion: 'SPDX-2.3'
  }, {
    source: createSource('reports/demo.spdx.json')
  });

  assert.equal(document.format, 'spdx');
  assert.equal(document.name, 'Demo SPDX Document');
  assert.equal(document.components[0]?.purl, 'pkg:npm/lodash@4.17.21');
  assert.equal(document.components[0]?.cpe, 'cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*');
  assert.equal(document.components[0]?.vulnerabilityCount, 0);
});

test('throws a clear error for unsupported JSON documents', () => {
  assert.throws(() => parseSbomJson({
    hello: 'world'
  }, {
    source: createSource('reports/not-an-sbom.json')
  }), /Unsupported SBOM JSON format in "reports\/not-an-sbom\.json"\. Supported formats: CycloneDX JSON and SPDX JSON\./);
});
