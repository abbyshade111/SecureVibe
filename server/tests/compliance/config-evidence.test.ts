/**
 * Checks that already know which requirements they verify credit them directly: the configuration checks say so in
 * `requirementIds`, and the evaluation counts that evidence for those requirements — a check the owner would
 * otherwise be asked to confirm by hand.
 */
import { describe, expect, it } from 'vitest';
import type { Evidence } from '@shared/compliance.js';
import { CONFIG_CHECKS } from '../../src/scanners/config/checks.js';
import { buildRequirementEvidence, type RequirementEvidenceCtx } from '../../src/compliance/evidence.js';
import { EvidenceIds } from '../../src/compliance/evidence-ids.js';
import { deriveDesign } from '../../src/design/index.js';
import { frameworksForTests, makeKnowledge } from '../fixtures/design/knowledge.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { manifestFixture } from '../fixtures/compliance/manifest.js';

const design = deriveDesign(habitTracker, { knowledge: makeKnowledge(), frameworks: frameworksForTests(), now: new Date('2026-09-16T10:00:00.000Z') });

function ctxWith(extraEvidence: Evidence[]): RequirementEvidenceCtx {
  return {
    standard: 'asvs',
    manifest: manifestFixture,
    manifestResults: [],
    testResults: [],
    probeResults: [],
    findings: [],
    extraEvidence,
    attestations: [],
    runMeta: { runId: 'run_1', mode: 'full', provider: 'anthropic' },
    design,
    ids: new EvidenceIds('E'),
    capturedAt: '2026-09-16T10:00:00.000Z',
  };
}

function configEvidence(ref: string, requirementIds: string[], passed: boolean): Evidence {
  return { id: 'E-0001', type: 'config', tier: 'medium', ref, summary: `${ref}: checked`, passed, tool: 'securevibe-config', producedBy: 'rules', requirementIds };
}

describe('evidence that names its own requirements', () => {
  it('credits the requirement the check declares, without the id appearing in the ref', () => {
    const ctx = ctxWith([configEvidence('config.no-debug-flags', ['V13.4.2'], true)]);
    expect(buildRequirementEvidence('V13.4.2', 'automatable', ctx).statusCtxPartial.evidence.map((e) => e.ref)).toContain('config.no-debug-flags');
    expect(buildRequirementEvidence('V13.4.1', 'automatable', ctx).statusCtxPartial.evidence.map((e) => e.ref)).not.toContain('config.no-debug-flags');
  });

  it('carries a failing check through, so a wrong setting is a failure and not a silent gap', () => {
    const ctx = ctxWith([configEvidence('config.no-debug-flags', ['V13.4.2'], false)]);
    const evidence = buildRequirementEvidence('V13.4.2', 'automatable', ctx).statusCtxPartial.evidence;
    expect(evidence.find((e) => e.ref === 'config.no-debug-flags')?.passed).toBe(false);
  });

  it('keeps crediting evidence that only mentions the requirement in its ref', () => {
    const legacy: Evidence = { id: 'E-0002', type: 'scanner', tier: 'medium', ref: 'deps.sbom-generated:V15.1.2', summary: 'An SBOM was generated.', passed: true };
    expect(buildRequirementEvidence('V15.1.2', 'automatable', ctxWith([legacy])).statusCtxPartial.evidence.map((e) => e.ref)).toContain('deps.sbom-generated:V15.1.2');
  });
});

describe('the configuration checks', () => {
  it('say which requirements they verify, so nothing has to be confirmed by hand for want of a mapping', () => {
    // These two are about SecureVibe's own record-keeping rather than an ASVS requirement.
    const general = new Set(['config.provenance-present', 'config.readme-run-instructions']);
    for (const check of CONFIG_CHECKS) {
      if (general.has(check.meta.id)) continue;
      expect([...check.meta.asvs, ...check.meta.aisvs].length, `${check.meta.id} declares no requirement`).toBeGreaterThan(0);
    }
  });
});
