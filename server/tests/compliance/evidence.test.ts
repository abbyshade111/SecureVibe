import { describe, expect, it } from 'vitest';
import { deriveDesign } from '../../src/design/index.js';
import { buildRequirementEvidence, refMentionsRequirement, testMatchesRequirement, type RequirementEvidenceCtx } from '../../src/compliance/evidence.js';
import { EvidenceIds } from '../../src/compliance/evidence-ids.js';
import type { AiReviewResult, ManifestControlResult, RunMeta } from '../../src/compliance/types.js';
import { frameworksForTests, makeKnowledge } from '../fixtures/design/knowledge.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { manifestFixture } from '../fixtures/compliance/manifest.js';

const knowledge = makeKnowledge();
const frameworks = frameworksForTests();
const design = deriveDesign(habitTracker, { knowledge, frameworks, now: new Date('2026-09-16T10:00:00.000Z') });

function baseRunMeta(overrides: Partial<RunMeta> = {}): RunMeta {
  return { runId: 'run_1', mode: 'full', provider: 'anthropic', ...overrides };
}

function baseCtx(overrides: Partial<RequirementEvidenceCtx> = {}): RequirementEvidenceCtx {
  return {
    standard: 'asvs',
    manifest: manifestFixture,
    manifestResults: [],
    testResults: [],
    probeResults: [],
    findings: [],
    extraEvidence: [],
    attestations: [],
    runMeta: baseRunMeta(),
    design,
    ids: new EvidenceIds('E'),
    capturedAt: '2026-09-16T10:00:00.000Z',
    ...overrides,
  };
}

describe('testMatchesRequirement / refMentionsRequirement', () => {
  it('matches a test name that starts with the id as a whole token', () => {
    expect(testMatchesRequirement('V6.2.1 rejects short passwords', 'V6.2.1')).toBe(true);
  });

  it('matches the test name inside a "suite > test" name, but not the suite name alone', () => {
    expect(testMatchesRequirement('password > V6.2.1 rejects short passwords', 'V6.2.1')).toBe(true);
    expect(testMatchesRequirement('V6.2.1 suite > something else', 'V6.2.1')).toBe(false);
  });

  it('does not confuse V6.2.1 with V6.2.10', () => {
    expect(testMatchesRequirement('V6.2.10 does something else', 'V6.2.1')).toBe(false);
  });

  it('finds a requirement id inside a colon-separated ref', () => {
    expect(refMentionsRequirement('config:V13.2.3', 'V13.2.3')).toBe(true);
    // A longer id that only starts with the same digits must not match.
    expect(refMentionsRequirement(`config:V13.2.${3}0`, 'V13.2.3')).toBe(false);
  });
});

describe('buildRequirementEvidence: manifest controls', () => {
  it('credits requirement-level medium evidence from a passing, expected manifest control', () => {
    const manifestResults: ManifestControlResult[] = [
      { controlId: 'TPL-AUTH-01', expected: true, checks: [], passed: true, creditedBy: ['test'], docOnly: false, errored: false, evidence: [] },
    ];
    const ctx = baseCtx({ manifestResults });
    const result = buildRequirementEvidence('V6.2.1', 'automatable', ctx);
    const e = result.statusCtxPartial.evidence.find((x) => x.type === 'template-control');
    expect(e?.passed).toBe(true);
    expect(e?.tier).toBe('medium');
  });

  it('marks partial-coverage control evidence so it can never carry a requirement past "partial"', () => {
    const manifestResults: ManifestControlResult[] = [
      { controlId: 'TPL-HEADERS-01', expected: true, checks: [], passed: true, creditedBy: ['dast'], docOnly: false, errored: false, evidence: [] },
    ];
    const ctx = baseCtx({ manifestResults });
    const result = buildRequirementEvidence('V3.4.3', 'automatable', ctx);
    const e = result.statusCtxPartial.evidence.find((x) => x.ref === 'TPL-HEADERS-01');
    expect(e).toBeDefined();
    expect(result.statusCtxPartial.partialCoverage.has(e!.id)).toBe(true);
  });

  it('produces no evidence for a control that is not expected in this build', () => {
    const manifestResults: ManifestControlResult[] = [{ controlId: 'TPL-AUTH-01', expected: false, checks: [], passed: false, creditedBy: [], docOnly: false, errored: false, evidence: [] }];
    const ctx = baseCtx({ manifestResults });
    const result = buildRequirementEvidence('V6.2.1', 'automatable', ctx);
    expect(result.statusCtxPartial.evidence.some((e) => e.ref === 'TPL-AUTH-01')).toBe(false);
  });
});

describe('buildRequirementEvidence: AI review', () => {
  const aiReview = (assessment: AiReviewResult['assessments'][number]): AiReviewResult => ({
    performed: true,
    model: 'claude-opus-5',
    promptHash: 'hash123',
    assessments: [assessment],
  });

  it('only counts an AI review with a verified citation and confidence >= medium', () => {
    const ctx = baseCtx({
      aiReview: aiReview({ requirementId: 'V8.2.2', status: 'pass', confidence: 'high', rationale: 'ownership is checked', citations: [{ file: 'src/features/_example/routes.ts', line: 10, verified: true }] }),
    });
    const result = buildRequirementEvidence('V8.2.2', 'ai-assistable', ctx);
    expect(result.statusCtxPartial.aiVerdict).toBe('pass');
    expect(result.statusCtxPartial.evidence.some((e) => e.type === 'ai-review')).toBe(true);
  });

  it('discards an AI review whose citation was not verified, and records why', () => {
    const ctx = baseCtx({
      aiReview: aiReview({ requirementId: 'V8.2.2', status: 'pass', confidence: 'high', rationale: 'looks fine', citations: [{ file: 'src/features/_example/routes.ts', line: 10, verified: false }] }),
    });
    const result = buildRequirementEvidence('V8.2.2', 'ai-assistable', ctx);
    expect(result.statusCtxPartial.aiVerdict).toBeUndefined();
    expect(result.statusCtxPartial.evidence.some((e) => e.type === 'ai-review')).toBe(false);
    expect(result.notVerifiedReason).toBe('citation-unverified');
  });

  it('discards a low-confidence AI review', () => {
    const ctx = baseCtx({
      aiReview: aiReview({ requirementId: 'V8.2.2', status: 'pass', confidence: 'low', rationale: 'not sure', citations: [{ file: 'src/features/_example/routes.ts', line: 10, verified: true }] }),
    });
    const result = buildRequirementEvidence('V8.2.2', 'ai-assistable', ctx);
    expect(result.statusCtxPartial.aiVerdict).toBeUndefined();
    expect(result.notVerifiedReason).toBe('low-confidence');
  });

  it('an AI review with no citations at all is never counted as evidence', () => {
    const ctx = baseCtx({ aiReview: aiReview({ requirementId: 'V8.2.2', status: 'pass', confidence: 'high', rationale: 'trust me', citations: [] }) });
    const result = buildRequirementEvidence('V8.2.2', 'ai-assistable', ctx);
    expect(result.statusCtxPartial.evidence).toEqual([]);
  });
});

describe('buildRequirementEvidence: AISVS Appendix C human code review (AC.4.1 / AC.4.4)', () => {
  it('AC.4.1 fails by default until a named person records a review (DESIGN §13.4)', () => {
    const ctx = baseCtx({ standard: 'aisvs-appendix-c' });
    const result = buildRequirementEvidence('AC.4.1', 'manual-only', ctx);
    const e = result.statusCtxPartial.evidence.find((x) => x.ref === 'manual:human-code-review');
    expect(e?.passed).toBe(false);
  });

  it('AC.4.1 is credited once a human review is recorded', () => {
    const ctx = baseCtx({
      standard: 'aisvs-appendix-c',
      humanReview: { reviewedBy: 'Priya Shah', reviewedAt: '2026-09-10T00:00:00.000Z', filesReviewed: ['src/security/authz.ts'], codeTreeHash: 'abc' },
    });
    const result = buildRequirementEvidence('AC.4.1', 'manual-only', ctx);
    const e = result.statusCtxPartial.evidence.find((x) => x.ref === 'manual:human-code-review');
    expect(e?.passed).toBe(true);
  });
});

describe('buildRequirementEvidence: not-verified reasons', () => {
  it('uses "demo-mode" when the provider is null and the class is ai-assistable', () => {
    const ctx = baseCtx({ runMeta: baseRunMeta({ provider: null }) });
    const result = buildRequirementEvidence('V8.2.5', 'ai-assistable', ctx);
    expect(result.notVerifiedReason).toBe('demo-mode');
  });

  it('uses "requires-human" for manual-only requirements', () => {
    const ctx = baseCtx();
    const result = buildRequirementEvidence('V11.1.1', 'manual-only', ctx);
    expect(result.notVerifiedReason).toBe('requires-human');
  });

  it('uses "requires-deployment" for deployment-time requirements', () => {
    const ctx = baseCtx();
    const result = buildRequirementEvidence('V4.1.2', 'deployment-time', ctx);
    expect(result.notVerifiedReason).toBe('requires-deployment');
  });
});

describe('buildRequirementEvidence: reviewed and skipped results', () => {
  it('adds nothing for a control left uncredited only because a check was skipped', () => {
    const manifestResults: ManifestControlResult[] = [
      {
        controlId: 'TPL-AUTH-01',
        expected: true,
        checks: [{ check: { type: 'test', name: 'V6.2.1' }, passed: false, detail: 'Not checked: skipped', skippedReason: 'skipped' }],
        passed: false,
        creditedBy: [],
        docOnly: false,
        errored: false,
        evidence: [],
      },
    ];
    const result = buildRequirementEvidence('V6.2.1', 'automatable', baseCtx({ manifestResults }));
    expect(result.statusCtxPartial.evidence.filter((x) => x.type === 'template-control')).toEqual([]);
  });

  it('ignores a failed runtime probe whose finding was marked a false positive', () => {
    const probe = { id: 'dast.headers.csp', group: 'headers', phase: 'test', requirementIds: ['V3.4.3'], passed: false, expected: 'x', observed: 'y', durationMs: 1 } as RequirementEvidenceCtx['probeResults'][number];
    const falsePositive = { source: 'dast', ruleId: 'dast.headers.csp', status: 'false-positive', mappings: { asvs: [], aisvs: [], sbd: [] } } as unknown as RequirementEvidenceCtx['findings'][number];
    const withDecision = buildRequirementEvidence('V3.4.3', 'automatable', baseCtx({ probeResults: [probe], findings: [falsePositive] }));
    expect(withDecision.statusCtxPartial.evidence.filter((x) => x.type === 'dast')).toEqual([]);
    const without = buildRequirementEvidence('V3.4.3', 'automatable', baseCtx({ probeResults: [probe] }));
    expect(without.statusCtxPartial.evidence.filter((x) => x.type === 'dast').map((x) => x.passed)).toEqual([false]);
  });
});
