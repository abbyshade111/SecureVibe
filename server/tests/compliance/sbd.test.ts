import { describe, expect, it } from 'vitest';
import type { Attestation } from '@shared/project.js';
import { deriveDesign } from '../../src/design/index.js';
import { evaluateSbd } from '../../src/compliance/sbd.js';
import type { ManifestControlResult, RunMeta } from '../../src/compliance/types.js';
import { frameworksForTests, makeKnowledge } from '../fixtures/design/knowledge.js';
import { allProfiles, habitTracker } from '../fixtures/design/profiles.js';

const knowledge = makeKnowledge();
const frameworks = frameworksForTests();
const NOW = new Date('2026-09-16T10:00:00.000Z');
const runMeta: RunMeta = { runId: 'run_1', mode: 'full', provider: 'anthropic' };

function mtSixAttested(): Attestation[] {
  return [{ id: 'AT-MT06', requirementId: 'MT-06', standard: 'sbd', result: 'yes', note: 'Rehearsed the plan on 2026-09-01.', attestedBy: 'Sam Rivera', attestedAt: '2026-09-01T00:00:00.000Z' }];
}

describe('evaluateSbd: escalation formula (CONTRACTS §7)', () => {
  it('matches "criticalNo.length > 0 || score >= threshold || any trigger fires" for every fixture profile, attested or not', () => {
    for (const { profile } of allProfiles) {
      for (const attestations of [[], mtSixAttested()]) {
        const design = deriveDesign(profile, { knowledge, frameworks, now: NOW, attestations });
        const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations, runMeta });
        const expected = sbd.criticalNo.length > 0 || sbd.score >= sbd.threshold || design.riskTriage.triggers.some((t) => t.triggered);
        expect(sbd.escalate).toBe(expected);
      }
    }
  });

  it('a critical "No" (MT-06 unattested) forces escalation even with an otherwise low-risk profile', () => {
    const design = deriveDesign(habitTracker, { knowledge, frameworks, now: NOW });
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations: [], runMeta });
    expect(sbd.criticalNo).toContain('MT-06');
    expect(sbd.escalate).toBe(true);
    expect(sbd.escalationReasons.length).toBeGreaterThan(0);
    expect(sbd.escalationHandling).toMatch(/Escalation required/);
  });

  it('escalation clears once the only critical "No" is attested away, for a profile with no other triggers', () => {
    const attestations = mtSixAttested();
    const design = deriveDesign(habitTracker, { knowledge, frameworks, now: NOW, attestations });
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations, runMeta });
    expect(sbd.criticalNo).toEqual([]);
    expect(sbd.escalate).toBe(false);
    expect(sbd.escalationHandling).toMatch(/No escalation required/);
  });
});

describe('evaluateSbd: an owner\'s "not applicable", with a reason', () => {
  it('takes a critical "No" out of the list, keeps the control visible, and says who decided and why', () => {
    const design = deriveDesign(habitTracker, { knowledge, frameworks, now: NOW });
    expect(design.riskTriage.criticalNo).toContain('MT-06');
    const attestations: Attestation[] = [
      { id: 'AT-1', requirementId: 'MT-06', standard: 'sbd', result: 'not-sure', note: '', attestedBy: 'Sam Rivera', attestedAt: '2026-09-20T00:00:00.000Z' },
      { id: 'AT-2', requirementId: 'MT-06', standard: 'sbd', result: 'not-applicable', note: 'One person uses this on one computer; there is nobody to rehearse an incident plan with.', attestedBy: 'Sam Rivera', attestedAt: '2026-09-24T00:00:00.000Z' },
    ];
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations, runMeta });
    expect(sbd.criticalNo).not.toContain('MT-06');
    const entry = sbd.entries.find((e) => e.id === 'MT-06')!;
    expect(entry.status).toBe('n-a');
    expect(entry.note).toContain('because One person uses this on one computer');
    expect(entry.note).toContain('Sam Rivera');
    expect(entry.note).toContain('2026-09-24');
    expect(sbd.notApplicableIds).toContain('MT-06');
    // The escalation formula still holds with the recomputed list.
    expect(sbd.escalate).toBe(sbd.criticalNo.length > 0 || sbd.score >= sbd.threshold || design.riskTriage.triggers.some((t) => t.triggered));
  });
});

describe('evaluateSbd: post-build verification of checklist entries', () => {
  const design = deriveDesign(habitTracker, { knowledge, frameworks, now: NOW });

  it('is "verified" when every referenced control resolved and passed', () => {
    const manifestResults: ManifestControlResult[] = [
      { controlId: 'TPL-TRUSTZONES-01', expected: true, checks: [], passed: true, creditedBy: ['test'], docOnly: false, errored: false, evidence: [] },
    ];
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults, attestations: [], runMeta });
    const as01 = sbd.entries.find((e) => e.id === 'AS-01')!;
    expect(as01.status).toBe('yes');
    expect(as01.verification).toBe('verified');
  });

  it('is "contradicted" when a referenced control failed on the generated code', () => {
    const manifestResults: ManifestControlResult[] = [
      { controlId: 'TPL-TRUSTZONES-01', expected: true, checks: [], passed: false, creditedBy: [], docOnly: false, errored: false, evidence: [] },
    ];
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults, attestations: [], runMeta });
    const as01 = sbd.entries.find((e) => e.id === 'AS-01')!;
    expect(as01.verification).toBe('contradicted');
  });

  it('is "design-only" when nothing in the build could check the referenced control', () => {
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations: [], runMeta });
    const as01 = sbd.entries.find((e) => e.id === 'AS-01')!;
    expect(as01.verification).toBe('design-only');
  });

  it('an "n-a" entry is always "verified" (nothing to contradict it)', () => {
    const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations: [], runMeta });
    const na = sbd.entries.find((e) => e.status === 'n-a');
    expect(na).toBeDefined();
    expect(na!.verification).toBe('verified');
  });
});

describe('evaluateSbd: process steps and deployment-time view', () => {
  const design = deriveDesign(habitTracker, { knowledge, frameworks, now: NOW });
  const sbd = evaluateSbd({ design, sbdRules: knowledge.sbdRules, sbd: frameworks.sbd, manifestResults: [], attestations: [], runMeta: { ...runMeta, approvedBy: 'Sam Rivera', approvedAt: '2026-09-16T09:00:00.000Z' } });

  it('has all 10 SbD process steps, numbered, with a performedBy for each', () => {
    expect(sbd.processSteps).toHaveLength(10);
    sbd.processSteps.forEach((s, i) => {
      expect(s.step).toBe(i + 1);
      expect(s.performedBy.length).toBeGreaterThan(0);
    });
  });

  it('step 9 (handoff to development) is completed once a human approval is recorded', () => {
    const handoff = sbd.processSteps[8]!;
    expect(handoff.name).toMatch(/Handoff/i);
    expect(handoff.performedBy).toBe('Sam Rivera');
    expect(handoff.completed).toBe(true);
  });

  it('carries a deployment-time entry for every checklist control', () => {
    expect(sbd.deploymentTime).toHaveLength(design.checklist.length);
    for (const d of sbd.deploymentTime) expect(['yes', 'no', 'n-a', 'deferred']).toContain(d.status);
  });
});
