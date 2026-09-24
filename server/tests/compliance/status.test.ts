import { describe, expect, it } from 'vitest';
import { EVIDENCE_TIER, type Evidence } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import { decideStatus, type StatusContext } from '../../src/compliance/status.js';

let evidenceCounter = 0;
function ev(partial: Partial<Evidence> & Pick<Evidence, 'type' | 'passed'>): Evidence {
  evidenceCounter += 1;
  return {
    id: `E-${evidenceCounter}`,
    ref: `ref-${evidenceCounter}`,
    summary: 'fixture evidence',
    tier: partial.tier ?? EVIDENCE_TIER[partial.type],
    ...partial,
  };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'F-1',
    fingerprint: 'fp-1',
    source: 'sast',
    sourcesReporting: [],
    ruleId: 'sast.example',
    title: 'Example finding',
    severity: 'high',
    priority: 'P2',
    exploitability: 'requires-network-exposure',
    confidence: 'high',
    cwe: [],
    description: '',
    impact: '',
    evidence: '',
    remediation: { summary: 'fix it', steps: [], references: [] },
    mappings: { asvs: [], aisvs: [], sbd: [] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'unknown',
    ...overrides,
  };
}

function baseCtx(overrides: Partial<StatusContext> = {}): StatusContext {
  return {
    verificationClass: 'automatable',
    manualOnly: false,
    evidence: [],
    partialCoverage: new Set(),
    openFindings: [],
    notVerifiedReason: 'no-check-available',
    ...overrides,
  };
}

describe('decideStatus: "not applicable", with a reason', () => {
  const decided = { id: 'AT-1', requirementId: 'V6.1.1', standard: 'asvs' as const, result: 'not-applicable' as const, note: 'We have no organisation-wide sign-in system; this app has three users on one computer.', attestedBy: 'Sam Rivera', attestedAt: '2026-09-24T10:00:00.000Z', evidenceLink: undefined };

  it('marks the requirement not applicable and says who decided, when and why', () => {
    const d = decideStatus(baseCtx({ attestation: decided }));
    expect(d.status).toBe('not-applicable');
    expect(d.rationale).toContain('because We have no organisation-wide sign-in system');
    expect(d.rationale).toContain('Sam Rivera');
    expect(d.rationale).toContain('2026-09-24');
    expect(d.rationale).toMatch(/owner's decision, not verified/);
    // Manual-only requirements too: the answer is a decision, not a confirmation.
    expect(decideStatus(baseCtx({ manualOnly: true, verificationClass: 'manual-only', attestation: decided })).status).toBe('not-applicable');
  });

  it('never overrides evidence that the requirement applies and fails', () => {
    const d = decideStatus(baseCtx({ attestation: decided, evidence: [ev({ type: 'test', passed: false })] }));
    expect(d.status).toBe('fail');
    const c = decideStatus(baseCtx({ attestation: decided, openFindings: [finding({ confidence: 'high', severity: 'high' })] }));
    expect(c.status).not.toBe('not-applicable');
  });
});

describe('decideStatus: honesty rules (DESIGN §13.1, CONTRACTS §9.4)', () => {
  it('never returns pass from weak evidence alone (AI review, design docs, attestations)', () => {
    const weakOnly = [
      ev({ type: 'ai-review', passed: true }),
      ev({ type: 'design', passed: true }),
      ev({ type: 'manual', passed: true, producedBy: 'owner:sam' }),
    ];
    for (const one of weakOnly) {
      const decision = decideStatus(baseCtx({ evidence: [one] }));
      expect(decision.status).not.toBe('pass');
    }
  });

  it('never returns pass from a single medium item (needs >=2 medium or >=1 strong)', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'template-control', passed: true })] }));
    expect(decision.status).toBe('partial');
  });

  it('returns pass from two independent passing medium items', () => {
    const decision = decideStatus(
      baseCtx({ evidence: [ev({ type: 'template-control', passed: true }), ev({ type: 'config', passed: true })] }),
    );
    expect(decision.status).toBe('pass');
  });

  it('returns pass from one passing strong item alone', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'test', passed: true })] }));
    expect(decision.status).toBe('pass');
  });

  it('caps a control with only partial coverage at "partial" even when it passes', () => {
    const e = ev({ type: 'template-control', passed: true });
    const decision = decideStatus(baseCtx({ evidence: [e], partialCoverage: new Set([e.id]) }));
    expect(decision.status).toBe('partial');
  });

  it('manual-only requirements can never be "pass" — a "yes" attestation becomes "attested" instead', () => {
    const decision = decideStatus(
      baseCtx({
        verificationClass: 'manual-only',
        manualOnly: true,
        attestation: { id: 'A-1', requirementId: 'V11.1.1', standard: 'asvs', result: 'yes', note: '', attestedBy: 'Sam', attestedAt: '2026-01-01T00:00:00Z' },
      }),
    );
    expect(decision.status).toBe('attested');
    expect(decision.status).not.toBe('pass');
  });

  it('manual-only requirements with no attestation are "not-verified", never "pass"', () => {
    const decision = decideStatus(baseCtx({ verificationClass: 'manual-only', manualOnly: true }));
    expect(decision.status).toBe('not-verified');
  });

  it('manual-only requirements a person answered "no" for are "fail"', () => {
    const decision = decideStatus(
      baseCtx({
        verificationClass: 'manual-only',
        manualOnly: true,
        attestation: { id: 'A-2', requirementId: 'V11.1.1', standard: 'asvs', result: 'no', note: '', attestedBy: 'Sam', attestedAt: '2026-01-01T00:00:00Z' },
      }),
    );
    expect(decision.status).toBe('fail');
  });

  it('a passing AI review alone (verified citation) is "ai-assessed", never "pass"', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'ai-review', passed: true })], aiVerdict: 'pass' }));
    expect(decision.status).toBe('ai-assessed');
  });

  it('documentation alone is "documented", never "pass"', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'design', passed: true })] }));
    expect(decision.status).toBe('documented');
  });

  it('an open, non-low-confidence finding mapped to the requirement fails it even with a passing weak item', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'ai-review', passed: true })], openFindings: [finding({ confidence: 'high' })] }));
    expect(decision.status).toBe('fail');
  });

  it('a low-confidence open finding does not fail the requirement on its own', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'test', passed: true })], openFindings: [finding({ confidence: 'low' })] }));
    expect(decision.status).toBe('pass');
  });

  it('an informational open finding does not fail the requirement, a low-severity one does', () => {
    const passing = [ev({ type: 'test', passed: true })];
    expect(decideStatus(baseCtx({ evidence: passing, openFindings: [finding({ severity: 'info' })] })).status).toBe('pass');
    expect(decideStatus(baseCtx({ evidence: passing, openFindings: [finding({ severity: 'low' })] })).status).not.toBe('pass');
  });

  it('a failing strong check fails the requirement outright', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'test', passed: false })] }));
    expect(decision.status).toBe('fail');
  });

  it('mixed strong pass + medium fail is "partial", not "fail" or "pass"', () => {
    const decision = decideStatus(baseCtx({ evidence: [ev({ type: 'test', passed: true }), ev({ type: 'config', passed: false })] }));
    expect(decision.status).toBe('partial');
  });

  it('with no evidence at all, falls back to not-verified with the supplied reason', () => {
    const decision = decideStatus(baseCtx({ notVerifiedReason: 'demo-mode' }));
    expect(decision.status).toBe('not-verified');
    expect(decision.notVerifiedReason).toBe('demo-mode');
  });
});
