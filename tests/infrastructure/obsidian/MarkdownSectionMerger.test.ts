import assert from 'node:assert/strict';
import test from 'node:test';
import { MarkdownSectionMerger } from '../../../src/infrastructure/obsidian/MarkdownSectionMerger';

const existingDocument = [
  '# VulnDash Briefing 2026-04-18',
  '',
  '<!-- VULNDASH:SECTION executive-summary START -->',
  '## Executive Summary',
  '',
  '- stale summary',
  '<!-- VULNDASH:SECTION executive-summary END -->',
  '',
  '## Analyst Notes',
  '',
  '- Analyst note that must survive.'
].join('\n');

test('MarkdownSectionMerger rewrites managed sections and preserves analyst notes', () => {
  const merger = new MarkdownSectionMerger();
  const merged = merger.merge({
    analystNotesHeading: '## Analyst Notes',
    analystNotesPlaceholder: '- Placeholder',
    existingContent: existingDocument,
    managedSections: [{
      content: ['## Executive Summary', '', '- fresh summary'].join('\n'),
      key: 'executive-summary'
    }, {
      content: ['## Action Items', '', '- [ ] Do the thing'].join('\n'),
      key: 'action-items'
    }],
    title: '# VulnDash Briefing 2026-04-18'
  });

  assert.match(merged, /fresh summary/);
  assert.match(merged, /<!-- VULNDASH:SECTION action-items START -->/);
  assert.match(merged, /Analyst note that must survive\./);
  assert.doesNotMatch(merged, /stale summary/);
});

test('MarkdownSectionMerger creates a fresh analyst notes placeholder when none exists', () => {
  const merged = new MarkdownSectionMerger().merge({
    analystNotesHeading: '## Analyst Notes',
    analystNotesPlaceholder: '- Placeholder',
    managedSections: [{
      content: '## Executive Summary\n\n- fresh summary',
      key: 'executive-summary'
    }],
    title: '# VulnDash Briefing 2026-04-18'
  });

  assert.match(merged, /## Analyst Notes/);
  assert.match(merged, /- Placeholder/);
});
