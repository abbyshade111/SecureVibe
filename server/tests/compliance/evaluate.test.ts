import { describe, expect, it } from 'vitest';
import { ComplianceResultSchema } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import type { Provenance } from '@shared/pipeline.js';
import { deriveDesign } from '../../src/design/index.js';
import { evaluateManifestControls } from '../../src/compliance/manifest-check.js';
import { evaluateCompliance } from '../../src/compliance/evaluate.js';
import type { AiReviewResult, EvaluateInput, ProbeResultLike, RunMeta, TestResult } from '../../src/compliance/types.js';
import { frameworksForTests, makeKnowledge } from '../fixtures/design/knowledge.js';
import { clinicBookings } from '../fixtures/design/profiles.js';
import { buildSpecFixture, makeManifestCheckContext } from '../fixtures/compliance/context.js';
import { manifestFixture } from '../fixtures/compliance/manifest.js';

const frameworks = frameworksForTests();
const knowledge = makeKnowledge({
  requirementsPlain: {
    'V11.1.1': {
      id: 'V11.1.1',
      plain: 'Cryptographic keys are generated and stored the right way.',
      manual: { whoCanDo: 'developer', steps: ['Review docs/crypto.md with a developer.'], estimatedEffort: 'hour' },
    },
  },
});
const NOW = new Date('2026-09-16T10:00:00.000Z');

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'F-0001',
    fingerprint: 'fp-0001',
    source: 'sast',
    sourcesReporting: ['sast'],
    ruleId: 'sast.example',
    title: 'Passwords are not checked against the common-password list',
    severity: 'high',
    priority: 'P1',
    exploitability: 'trivial',
    confidence: 'high',
    cwe: ['CWE-521'],
    description: 'Weak passwords are accepted.',
    impact: 'An attacker can guess a common password.',
    evidence: 'src/security/password.ts does not call the common-password check.',
    remediation: { summary: 'Call checkCommonPassword() before accepting a new password.', steps: [], references: [] },
    mappings: { asvs: ['V6.2.1'], aisvs: [], sbd: [] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'ai-generated',
    ...overrides,
  };
}

function buildInput(overrides: Partial<EvaluateInput> = {}): { input: EvaluateInput; design: ReturnType<typeof deriveDesign>; manifestCtx: ReturnType<typeof makeManifestCheckContext> } {
  const design = deriveDesign(clinicBookings, { knowledge, frameworks, now: NOW });
  const buildSpec = design.buildSpec;

  const testResults: TestResult[] = [
    { name: 'V8.2.2 ownership is enforced for owner-scoped entities', ok: true, file: 'tests/security/authz.test.ts' },
    { name: 'C2.1.1 normalises AI input to NFKC', ok: true, file: 'tests/security/ai.test.ts' },
  ];
  const probeResults: ProbeResultLike[] = [
    { id: 'dast.headers.csp', passed: true, observed: 'Content-Security-Policy present with a per-request nonce.', requirementIds: ['V3.4.3', 'V3.4.6'] },
  ];

  const manifestCtx = makeManifestCheckContext({
    buildSpec,
    testResults: [{ name: 'V6.2.1 rejects short passwords', ok: false, file: 'tests/security/password.test.ts' }],
    probeResults,
  });

  const aiReview: AiReviewResult = {
    performed: true,
    model: 'claude-opus-5',
    promptHash: 'hash-abc',
    assessments: [
      {
        requirementId: 'C5.2.1',
        status: 'pass',
        confidence: 'high',
        rationale: 'Application data is fetched only through repository functions scoped to req.user.',
        citations: [{ file: 'src/features/ai/index.ts', line: 3, verified: true }],
      },
    ],
    reviewedRequirementIds: ['C5.2.1'],
    unverifiedCitations: 0,
  };

  const runMeta: RunMeta = {
    runId: 'run_0001',
    mode: 'full',
    provider: 'anthropic',
    model: 'claude-opus-5',
    generatedAt: NOW.toISOString(),
    approvedBy: 'Dr Lee Okafor',
    approvedAt: NOW.toISOString(),
    auditLogPresent: true,
    screeningPerformed: true,
    screeningEvents: 4,
    sandbox: { mode: 'node-permission-model', note: "Generated code runs under Node's permission model restricted to the project folder; network access is not restricted." },
    deploymentTarget: 'internet-later',
    provenance: {
      reportSchemaVersion: '1.0.0',
      tool: 'SecureVibe 0.1.0',
      securevibeVersion: '0.1.0',
      templateVersion: '0.0.1',
      frameworkVersions: { asvs: frameworks.asvs.version, aisvs: frameworks.aisvs.version, sbd: frameworks.sbd.version },
      toolVersions: {},
      runId: 'run_0001',
      projectId: 'p_fixture',
      generatedAt: NOW.toISOString(),
      mode: 'full',
      humanInvolvement: { summary: 'Design confirmed and build approved by Dr Lee Okafor.', buildApprovedAt: NOW.toISOString(), approvedBy: 'Dr Lee Okafor', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
      designProfileHash: 'x',
      designHash: 'y',
      codeTreeHash: 'z',
      generatedFiles: [],
      protectedFileHashes: {},
      sandbox: { mode: 'node-permission-model', note: 'network access is not restricted' },
    } satisfies Provenance,
  };

  return {
    design,
    manifestCtx,
    input: {
      design,
      profile: clinicBookings,
      manifest: manifestFixture,
      manifestResults: [],
      findings: [finding()],
      evidence: [],
      testResults,
      probeResults,
      aiReview,
      attestations: [],
      runMeta,
      knowledge,
      frameworks,
      ...overrides,
    },
  };
}

describe('evaluateCompliance: end-to-end shape and honesty', () => {
  it('produces a ComplianceResult that validates against the shared schema', async () => {
    const { input, manifestCtx } = buildInput();
    input.manifestResults = await evaluateManifestControls(manifestFixture, manifestCtx);

    const result = evaluateCompliance(input);
    expect(() => ComplianceResultSchema.parse(result)).not.toThrow();
    return result;
  });

  it('fails V6.2.1: an open, high-confidence finding with no passing evidence', async () => {
    const { input, manifestCtx } = buildInput();
    input.manifestResults = await evaluateManifestControls(manifestFixture, manifestCtx);
    const result = evaluateCompliance(input);

    const v621 = result.asvs.results.find((r) => r.id === 'V6.2.1');
    expect(v621?.status).toBe('fail');
    expect(v621?.findingIds).toContain('F-0001');
    expect(v621?.remediation).toContain('F-0001');
  });

  it('credits V8.2.2 and C2.1.1 from a directly-matching test name, without any manifest control', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    const v822 = result.asvs.results.find((r) => r.id === 'V8.2.2');
    expect(v822?.status).toBe('pass');
    const aisvs = result.aisvs;
    expect(aisvs).toBeDefined();
    const c211 = aisvs!.results.find((r) => r.id === 'C2.1.1');
    expect(c211?.status).toBe('pass');
  });

  it('credits V3.4.3 from a runtime probe naming it in requirementIds', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    const v343 = result.asvs.results.find((r) => r.id === 'V3.4.3');
    expect(v343?.status).toBe('pass');
  });

  it('only accepts a verified, medium-or-better-confidence AI review as evidence (C5.2.1 becomes ai-assessed, never pass)', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    const c521 = result.aisvs!.results.find((r) => r.id === 'C5.2.1');
    expect(c521).toBeDefined();
    expect(c521!.status).toBe('ai-assessed');
    expect(c521!.status).not.toBe('pass');
  });

  it('AISVS Appendix C AC.4.1 fails until a named human code review is recorded (DESIGN §13.4)', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    const ac41 = result.appendixC!.results.find((r) => r.id === 'AC.4.1');
    expect(ac41?.status).toBe('fail');

    const withReview = evaluateCompliance({
      ...input,
      humanReview: { reviewedBy: 'Priya Shah', reviewedAt: NOW.toISOString(), filesReviewed: ['src/security/authz.ts'], codeTreeHash: 'zzz' },
    });
    const ac41b = withReview.appendixC!.results.find((r) => r.id === 'AC.4.1');
    expect(ac41b?.status).toBe('attested');
  });

  it('lists a manual-only, plain-language requirement in manualVerification, grouped by who can do it', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    const row = result.manualVerification.find((m) => m.requirementId === 'V11.1.1');
    expect(row).toBeDefined();
    expect(row!.manual.whoCanDo).toBe('developer');
  });

  it('reports the overall headline as "N of M applicable Level L ASVS requirements verified passing" and never says compliant/certified', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    expect(result.overall.headline).toMatch(/^\d+ of \d+ applicable Level \d ASVS requirements verified passing/);
    const text = [result.overall.headline, result.overall.canIUseIt, result.methodology, ...result.limitations, ...result.asvs.results.map((r) => r.rationale)].join(' ');
    expect(text).not.toMatch(/\bcompliant\b/i);
    expect(text).not.toMatch(/\bcertified\b/i);
  });

  it('gates "Can I use it?" on open P1 findings, and says which one', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    expect(result.overall.canIUseIt).toMatch(/urgent/i);

    // Counting the blockers without naming them sent an owner to a list of five actions that did not contain the
    // blocker — a finding SecureVibe fixes itself never becomes an action, because an action is something a
    // person does. The verdict must name the thing it is talking about and point somewhere it can be found.
    const blockers = input.findings.filter((f) => f.priority === 'P1' && f.status === 'open');
    expect(blockers.length).toBeGreaterThan(0);
    expect(result.overall.canIUseIt).toContain(blockers[0]!.title);
    expect(result.overall.canIUseIt).toContain('What we found');
    expect(result.overall.canIUseIt).not.toMatch(/issue need fixing/);

    const clean = evaluateCompliance({ ...input, findings: [] });
    expect(clean.overall.canIUseIt).not.toMatch(/urgent/i);
  });

  it('recommendations are sorted high, then medium, then low priority, and top 5 mirrors overall.topActions', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    const rank = { high: 0, medium: 1, low: 2 } as const;
    for (let i = 1; i < result.recommendations.length; i++) {
      expect(rank[result.recommendations[i]!.priority]).toBeGreaterThanOrEqual(rank[result.recommendations[i - 1]!.priority]);
    }
    expect(result.overall.topActions).toEqual(result.recommendations.slice(0, 5));
    expect(result.overall.topActions.length).toBeLessThanOrEqual(5);
  });

  it('traceability has one row per design security requirement, each with a valid status', async () => {
    const { input, design } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance(input);
    expect(result.traceability).toHaveLength(design.securityRequirements.length);
    for (const row of result.traceability) expect(['verified', 'partially-verified', 'not-verified', 'failing']).toContain(row.status);
  });

  it('reports no change when re-evaluated against itself as the previous run', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const first = evaluateCompliance(input);
    const second = evaluateCompliance({ ...input, previous: first, previousFindings: input.findings });
    expect(second.changesSincePrevious).toEqual({ improved: [], regressed: [], newFindings: 0, fixedFindings: 0 });
  });

  it('records a preview-mode ("demo-mode") reason when no AI provider is configured', async () => {
    const { input } = buildInput();
    input.manifestResults = [];
    const result = evaluateCompliance({ ...input, aiReview: undefined, runMeta: { ...input.runMeta, provider: null } });
    const aiOnly = result.aisvs!.results.find((r) => r.verificationClass === 'ai-assistable' && r.status === 'not-verified');
    expect(aiOnly?.notVerifiedReason).toBe('demo-mode');
  });
});
