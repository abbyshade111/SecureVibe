/** Checks left out of a run say why, in words that fit the target: an uploaded app, or SecureVibe itself. */
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { SELF_ASSESS_EXCLUDED_CHECKS, SELF_ASSESS_EXCLUDED_REASON } from '../../src/cli/self-assess-support.js';
import { absorbScanResult } from '../../src/pipeline/stage-helpers.js';
import { ALL_RULES } from '../../src/scanners/sast/rules/index.js';

function fakeCtx(excluded: string[], reason?: string) {
  const logRoot = mkdtempSync(join(tmpdir(), 'securevibe-excluded-'));
  return {
    store: { projectPath: (...parts: string[]) => join(logRoot, ...parts) },
    project: { id: 'p_aaaaaaaaaa' },
    excludedChecks: new Set(excluded),
    ...(reason ? { excludedChecksReason: reason } : {}),
    acc: { findings: [] as { ruleId: string }[], evidence: [] as { ref: string }[], coverage: [] as unknown[] },
    run: { id: 'r_20260924120000_abcdef', stages: [] as { id: string; status: string; summary: string }[] },
    bus: { stage: () => undefined, log: () => undefined },
    log: () => undefined,
  };
}

const sastResult = (ruleIds: string[]) => ({
  status: 'failed' as const,
  summary: `Static analysis found ${ruleIds.length} issues.`,
  findings: ruleIds.map((ruleId) => ({ ruleId })),
  evidence: [],
  coverage: { tool: 'securevibe-sast', ran: true },
  details: {},
});

describe('checks that do not apply to the target', () => {
  it('the four rules that misfired on SecureVibe are real rule ids, and only those four', () => {
    const ids = new Set(ALL_RULES.map((r) => r.id));
    for (const id of SELF_ASSESS_EXCLUDED_CHECKS) expect(ids.has(id), id).toBe(true);
    expect(SELF_ASSESS_EXCLUDED_CHECKS).toHaveLength(4);
  });

  it('drops them from a self-assessment and says why in the build tool\'s own terms', () => {
    const ctx = fakeCtx(SELF_ASSESS_EXCLUDED_CHECKS, SELF_ASSESS_EXCLUDED_REASON);
    const stage = absorbScanResult(ctx as never, 'sast', new Date(), sastResult(['sast.route-outside-registry', 'sast.child-process-exec', 'sast.sql-injection']) as never);
    expect(ctx.acc.findings.map((f) => f.ruleId)).toEqual(['sast.sql-injection']);
    expect(stage.summary).toContain('SecureVibe is a build tool');
    expect(stage.summary).toMatch(/2 check\(s\)/);
    // The real finding is still there, so the step still fails on it.
    expect(stage.status).toBe('failed');
  });

  it('keeps the uploaded-app wording when no other reason is given', () => {
    const ctx = fakeCtx(['sast.route-outside-registry']);
    const stage = absorbScanResult(ctx as never, 'sast', new Date(), sastResult(['sast.route-outside-registry']) as never);
    expect(stage.summary).toContain('only apply to apps built by SecureVibe');
    expect(stage.status).toBe('passed');
  });
});
