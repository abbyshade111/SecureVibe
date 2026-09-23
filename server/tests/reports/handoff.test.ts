/** HANDOFF.md: written from the run record, plain language, honest about what was and was not verified. */
import { describe, expect, it } from 'vitest';
import type { PipelineRun } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';
import { handoffMarkdown } from '../../src/reports/handoff.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { markdownCells } from '../fixtures/markdown-cells.js';

function project(over: Partial<Project> = {}): Project {
  return {
    id: 'p_handoff000',
    name: 'Habit Log',
    createdAt: '2026-09-17T10:00:00.000Z',
    updatedAt: '2026-09-17T10:00:00.000Z',
    profile: habitTracker,
    wizardStep: 0,
    status: 'built',
    runs: [],
    designStale: false,
    buildStale: false,
    appVersion: 0,
    attestations: [
      { id: 'a1', requirementId: 'V1.2.3', standard: 'asvs', result: 'yes', note: '', attestedBy: 'Abby', attestedAt: '2026-09-17T11:00:00.000Z' },
      { id: 'a2', requirementId: 'MT-06', standard: 'sbd', result: 'no', note: 'no backups yet', attestedBy: 'Abby', attestedAt: '2026-09-17T11:00:00.000Z' },
    ],
    findingDecisions: [],
    design: { buildSpec: { features: { tlsMode: 'off', lanBinding: false } } } as unknown as Project['design'],
    ...over,
  } as Project;
}

function run(over: Partial<PipelineRun> = {}): PipelineRun {
  return {
    id: 'r_20260917120000_hand00',
    projectId: 'p_handoff000',
    mode: 'full',
    startedAt: '2026-09-17T12:00:00.000Z',
    finishedAt: '2026-09-17T12:20:00.000Z',
    status: 'succeeded',
    stages: [{ id: 'unit-tests', status: 'passed', summary: '', details: { total: 100, passed: 98, failed: 2 } }],
    findings: [
      { id: 'F-0001', severity: 'high', status: 'open', title: 'Weak | password accepted', whoCanFix: 'developer', remediation: { summary: 'Enforce 12 characters.' }, location: { file: 'src/auth.ts', line: 10 } },
      { id: 'F-0002', severity: 'low', status: 'open', title: 'Minor', whoCanFix: 'owner', remediation: { summary: 'Decide.' } },
      { id: 'F-0003', severity: 'critical', status: 'fixed', title: 'Was fixed', whoCanFix: 'securevibe', remediation: { summary: '' } },
    ],
    coverage: [],
    artifacts: [],
    fixRounds: 0,
    incomplete: false,
    compliance: {
      overall: { rating: 'needs-attention', headline: 'Mostly there.', canIUseIt: 'Use it on one computer for now.' },
      asvs: { summary: { version: '5.0', targetLevel: 1, counts: { pass: 20 }, applicableCount: 25, verifiedPassPercent: 80 }, results: [] },
    },
    provenance: { templateVersion: '0.1.0', generatedFiles: [{ path: 'a', origin: 'template' }, { path: 'b', origin: 'ai-generated' }], sandbox: { mode: 'node-permission-model', note: 'network not restricted' } },
    ...over,
  } as unknown as PipelineRun;
}

describe('handoffMarkdown', () => {
  it('describes the app, the checks, the open problems, the human checks and what to do next', () => {
    const md = handoffMarkdown({ project: project(), run: run(), securevibeVersion: '0.1.0', contents: [{ path: 'HANDOFF.md', what: 'this document' }], now: new Date('2026-09-18T00:00:00Z') });
    expect(md).toContain('# Habit Log — hand-off pack');
    expect(md).toContain('npm run setup');
    expect(md).toContain('**NEEDS ATTENTION** — Mostly there.');
    expect(md).toContain('**80%** of applicable requirements verified');
    expect(md).toContain('98 of 100 passed, 2 failed');
    // Open problems: most serious first, fixed ones left out, pipe characters escaped for the table.
    expect(md).toContain('| high | Weak \\| password accepted (`src/auth.ts:10`) | a developer | Enforce 12 characters. |');
    expect(md).not.toContain('Was fixed');
    expect(md.indexOf('| high |')).toBeLessThan(md.indexOf('| low |'));
    expect(md).toContain('2 human check(s) answered: 1 yes, 1 no, 0 not sure');
    expect(md).toContain('- MT-06 — no backups yet');
    expect(md).toContain('runs over plain HTTP');
    expect(md).toContain('Fix or formally accept the critical/high problems');
    expect(md).toContain('1 SecureVibe template, 1 written by Claude');
    expect(md).toContain('- `HANDOFF.md` — this document');
  });

  it('does not let a finding title overwrite the column beside it', () => {
    // A finding title can come from a scanner, an AI review or a file name in the app being
    // checked — none of them written by anyone on this project. Escaping the pipe but not the
    // backslash lets `\\|` end the cell early, and whatever follows lands in "Who can fix it".
    const md = handoffMarkdown({
      project: project(),
      run: run({
        findings: [
          {
            id: 'F-0009',
            severity: 'high',
            status: 'open',
            title: 'Odd name x\\|SecureVibe|nothing to do here',
            whoCanFix: 'developer',
            remediation: { summary: 'Look at it.' },
          },
        ],
      } as Partial<PipelineRun>),
      securevibeVersion: '0.1.0',
      contents: [],
    });
    const row = md.split('\n').find((l) => l.includes('Odd name'))!;
    expect(row).toBeDefined();
    // The row must still have its four columns, and the third must be the real one.
    const cells = markdownCells(row);
    expect(cells).toHaveLength(4);
    expect(cells[2]).not.toContain('nothing to do here');
  });

  it('is honest when nothing was answered or evaluated', () => {
    const md = handoffMarkdown({ project: project({ attestations: [] }), run: run({ compliance: undefined, findings: [], provenance: undefined }), securevibeVersion: '0.1.0', contents: [] });
    expect(md).toContain('Nobody has answered the human checks yet');
    expect(md).toContain('The compliance evaluation did not run');
    expect(md).toContain('No open problems were found');
    expect(md).toContain('The provenance record was not available');
  });
});
