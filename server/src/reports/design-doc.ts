/** design.md: the design engine's own rendering when available, otherwise a minimal fallback built from DesignArtifacts alone. */
import { renderDesignMarkdown } from '../design/index.js';
import { mdBullets, mdTable } from './md.js';
import type { ReportModel } from './types.js';

export function renderDesignDoc(input: ReportModel): string {
  if (input.designMarkdown) return input.designMarkdown;
  if (input.profile) return renderDesignMarkdown(input.design, input.profile)['design.md'];

  const d = input.design;
  return [
    '# Design document',
    '',
    'Rendered without the full design profile; some sections that need the wizard answers directly are omitted.',
    '',
    '## What we will build',
    '',
    d.plainLanguageSummary,
    '',
    '## Security requirements',
    '',
    mdTable(['Id', 'Requirement', 'Category'], d.securityRequirements.map((r) => [r.id, r.statement, r.category])),
    '',
    '## Secure by Design checklist',
    '',
    mdTable(['Id', 'Status', 'Justification'], d.checklist.map((e) => [e.id, e.status, e.justification])),
    '',
    '## Assumptions',
    '',
    mdBullets(d.architecture.assumptions),
    '',
    '## Diagram',
    '',
    '```mermaid',
    d.architecture.mermaid,
    '```',
    '',
  ].join('\n');
}
