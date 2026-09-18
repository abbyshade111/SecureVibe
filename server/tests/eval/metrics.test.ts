/** Evaluation harness: metrics from a run, and the comparison rules against a baseline. */
import { describe, expect, it } from 'vitest';
import type { PipelineRun } from '@shared/pipeline.js';
import { compareMetrics, metricsOf, summaryLine, type EvalMetrics } from '../../src/eval/metrics.js';

function run(over: Partial<PipelineRun> = {}): PipelineRun {
  return {
    id: 'r_20260917120000_eval00',
    projectId: 'p_eval',
    mode: 'full',
    startedAt: '2026-09-17T12:00:00.000Z',
    finishedAt: '2026-09-17T12:05:00.000Z',
    status: 'succeeded',
    stages: [
      { id: 'scaffold', status: 'passed', summary: '' },
      { id: 'unit-tests', status: 'passed', summary: '', details: { total: 40, passed: 39, failed: 1 } },
    ],
    findings: [
      { id: 'F-0001', severity: 'high', status: 'open' },
      { id: 'F-0002', severity: 'high', status: 'fixed' },
      { id: 'F-0003', severity: 'low', status: 'open' },
    ],
    coverage: [],
    artifacts: [],
    fixRounds: 0,
    incomplete: false,
    compliance: {
      asvs: { summary: { counts: { pass: 80, 'ai-assessed': 5, fail: 2 }, applicableCount: 160, verifiedPassPercent: 50 }, results: [] },
      aisvs: { summary: { counts: { pass: 10, fail: 0 }, applicableCount: 40, verifiedPassPercent: 25 }, results: [] },
    },
    llmUsage: { provider: 'anthropic', model: 'm', calls: 3, estimatedCostUsd: 1.234 },
    ...over,
  } as unknown as PipelineRun;
}

describe('metricsOf', () => {
  it('counts only open problems, reads test counts and coverage, and rounds the cost', () => {
    const m = metricsOf(run(), 'habit-tracker', 'ai');
    expect(m.openFindings).toEqual({ critical: 0, high: 1, medium: 0, low: 1, info: 0 });
    expect(m.tests).toEqual({ total: 40, passed: 39, failed: 1 });
    expect(m.asvs).toEqual({ pass: 80, applicable: 160, verifiedPassPercent: 50, aiAssessed: 5, fail: 2 });
    expect(m.aisvs?.verifiedPassPercent).toBe(25);
    expect(m.costUsd).toBe(1.23);
    expect(m.durationMs).toBe(5 * 60_000);
    expect(m.stages).toEqual({ scaffold: 'passed', 'unit-tests': 'passed' });
    expect(summaryLine(m)).toContain('ASVS 50% verified (80/160)');
  });
});

describe('compareMetrics', () => {
  const baseline = metricsOf(run(), 'habit-tracker', 'no-ai');

  it('reports nothing for an identical result', () => {
    const c = compareMetrics(baseline, metricsOf(run(), 'habit-tracker', 'no-ai'));
    expect(c).toEqual({ regressions: [], improvements: [], notes: [] });
  });

  it('flags a build that stopped succeeding, a step that now fails, and more open serious problems', () => {
    const worse = metricsOf(
      run({
        status: 'failed',
        stages: [
          { id: 'scaffold', status: 'passed', summary: '' },
          { id: 'unit-tests', status: 'failed', summary: '', details: { total: 40, passed: 30, failed: 10 } },
        ] as PipelineRun['stages'],
        findings: [
          { id: 'F-0001', severity: 'high', status: 'open' },
          { id: 'F-0004', severity: 'critical', status: 'open' },
        ] as PipelineRun['findings'],
      }),
      'habit-tracker',
      'no-ai',
    );
    const c = compareMetrics(baseline, worse);
    expect(c.regressions).toEqual(
      expect.arrayContaining([
        expect.stringContaining('no longer succeeds'),
        expect.stringContaining('"unit-tests" went from passed to failed'),
        expect.stringContaining('Open critical problems went from 0 to 1'),
        expect.stringContaining('Failing app tests went from 1 to 10'),
        expect.stringContaining('Passing app tests went from 39 to 30'),
      ]),
    );
    // A change in low-severity items is worth a note, never a failure.
    expect(c.notes).toEqual(expect.arrayContaining([expect.stringContaining('low items went from 1 to 0')]));
  });

  it('tolerates a one-point wobble in verified coverage but flags a real drop, and credits a rise', () => {
    const wobble: EvalMetrics = { ...baseline, asvs: { ...baseline.asvs!, verifiedPassPercent: 49.2 } };
    expect(compareMetrics(baseline, wobble).regressions).toEqual([]);
    const drop: EvalMetrics = { ...baseline, asvs: { ...baseline.asvs!, verifiedPassPercent: 45, pass: 72 } };
    expect(compareMetrics(baseline, drop).regressions).toEqual([expect.stringContaining('ASVS verified coverage fell from 50% to 45%')]);
    const rise: EvalMetrics = { ...baseline, aisvs: { ...baseline.aisvs!, verifiedPassPercent: 30 } };
    expect(compareMetrics(baseline, rise).improvements).toEqual([expect.stringContaining('AISVS verified coverage rose from 25% to 30%')]);
  });

  it('notes cost and time, and flags planned features that stopped being built', () => {
    const b: EvalMetrics = { ...baseline, mode: 'ai', costUsd: 2, planCoverage: { built: 4, partly: 0, notBuilt: 0 } };
    const c: EvalMetrics = { ...b, costUsd: 4, durationMs: b.durationMs * 3, planCoverage: { built: 2, partly: 1, notBuilt: 1 } };
    const cmp = compareMetrics(b, c);
    expect(cmp.notes).toEqual(expect.arrayContaining([expect.stringContaining('Cost rose from $2.00 to $4.00'), expect.stringContaining('Took')]));
    expect(cmp.regressions).toEqual([expect.stringContaining('Planned features not built went from 0 to 1')]);
  });

  it('treats a standard that is no longer assessed as a regression', () => {
    const { aisvs: _dropped, ...withoutAisvs } = baseline;
    expect(compareMetrics(baseline, withoutAisvs as EvalMetrics).regressions).toEqual([expect.stringContaining('AISVS was not assessed')]);
  });
});
