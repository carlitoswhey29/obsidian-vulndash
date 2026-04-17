import assert from 'node:assert/strict';
import test from 'node:test';
import { ComponentNotePathResolver } from '../../../src/application/sbom/ComponentStorageResolver';

test('prefers exact semantic identifier matches before title-based fallback', () => {
  const resolver = new ComponentNotePathResolver([
    {
      basename: 'Lodash',
      frontmatter: {
        purl: 'pkg:npm/lodash@4.17.21'
      },
      path: 'Components/Lodash.md'
    },
    {
      basename: 'Widget',
      frontmatter: {
        cpe: 'cpe:2.3:a:acme:widget:2.3.4:*:*:*:*:*:*:*'
      },
      path: 'Components/Widget.md'
    },
    {
      basename: 'Portal Api Dependency',
      frontmatter: {
        name: 'portal-api',
        version: '1.2.3'
      },
      path: 'Architecture/Portal Api Dependency.md'
    }
  ]);

  assert.equal(resolver.resolve({
    name: 'lodash',
    purl: 'PKG:NPM/LODASH@4.17.21',
    version: '4.17.21'
  }), 'Components/Lodash.md');
  assert.equal(resolver.resolve({
    cpe: 'CPE:2.3:A:ACME:WIDGET:2.3.4:*:*:*:*:*:*:*',
    name: 'widget',
    version: '2.3.4'
  }), 'Components/Widget.md');
  assert.equal(resolver.resolve({
    name: 'Portal API',
    version: '1.2.3'
  }), 'Architecture/Portal Api Dependency.md');
});

test('uses exact normalized basename fallback when the match is unique', () => {
  const resolver = new ComponentNotePathResolver([
    {
      basename: 'Acme Widget',
      path: 'Components/Acme Widget.md'
    }
  ]);

  assert.equal(resolver.resolve({
    name: 'acme-widget'
  }), 'Components/Acme Widget.md');
});

test('returns null for ambiguous or unsupported matches', () => {
  const resolver = new ComponentNotePathResolver([
    {
      basename: 'Platform Api',
      path: 'Components/Platform Api.md'
    },
    {
      basename: 'Platform Api',
      path: 'Products/Platform Api.md'
    }
  ]);

  assert.equal(resolver.resolve({
    name: 'platform-api'
  }), null);
  assert.equal(resolver.resolve({
    name: 'platform-api',
    version: '2.0.0'
  }), null);
});
