/** A full, schema-valid ReportModel built from the compliance fixtures, for the reports module's tests. */
import type { ToolCoverage, Provenance, PipelineRun } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';
import { deriveDesign } from '../../../src/design/index.js';
import { evaluateCompliance } from '../../../src/compliance/evaluate.js';
import { evaluateManifestControls } from '../../../src/compliance/manifest-check.js';
import type { AiReviewResult, RunMeta, TestResult } from '../../../src/compliance/types.js';
import type { ProbeResultLike } from '../../../src/compliance/types.js';
import type { ReportModel } from '../../../src/reports/types.js';
import { frameworksForTests, makeKnowledge } from '../design/knowledge.js';
import { clinicBookings } from '../design/profiles.js';
import { buildSpecFixture, makeManifestCheckContext } from '../compliance/context.js';
import { manifestFixture } from '../compliance/manifest.js';
import type { Finding } from '@shared/findings.js';

const NOW = new Date('2026-09-16T10:00:00.000Z');

export const reportsKnowledge = makeKnowledge({
  glossary: [
    { term: 'CSRF', plain: 'A trick that makes your browser send a request you did not mean to send.' },
    { term: 'CSP', plain: 'A rule the app sends to your browser about which scripts are allowed to run.' },
  ],
  requirementsPlain: {
    'V11.1.1': { id: 'V11.1.1', plain: 'Cryptographic keys are generated and stored the right way.', manual: { whoCanDo: 'developer', steps: ['Review docs/crypto.md with a developer.'], estimatedEffort: 'hour' } },
  },
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'F-0001',
    fingerprint: 'fp-0001',
    source: 'sast',
    sourcesReporting: ['sast'],
    ruleId: 'sast.example',
    title: 'Passwords are not checked against the common-password list',
    severity: 'high',
    severityBase: 'high',
    priority: 'P1',
    exploitability: 'trivial',
    confidence: 'high',
    cwe: ['CWE-521'],
    location: { file: 'src/security/password.ts', line: 12 },
    description: 'Weak passwords are accepted.',
    impact: 'An attacker can guess a common password.',
    evidence: 'src/security/password.ts does not call the common-password check.',
    remediation: { summary: 'Call checkCommonPassword() before accepting a new password.', steps: ['Import checkCommonPassword.', 'Call it in the register/change-password handlers.'], example: "if (isCommonPassword(pw)) return fail('too common');", references: ['https://owasp.org'] },
    verification: { howToConfirmFixed: 'Re-run the password test suite.', rerunCommand: 'npm test -- password' },
    mappings: { asvs: ['V6.2.1'], aisvs: [], sbd: [] },
    status: 'open',
    whoCanFix: 'developer',
    introducedBy: 'ai-generated',
    firstSeenRun: 'run_0000',
    lastSeenRun: 'run_0001',
    ...overrides,
  };
}

export async function buildReportModel(outDir: string, appDir: string): Promise<ReportModel> {
  const knowledge = reportsKnowledge;
  const frameworks = frameworksForTests();
  const design = deriveDesign(clinicBookings, { knowledge, frameworks, now: NOW });

  const testResults: TestResult[] = [{ name: 'V8.2.2 ownership is enforced', ok: true, file: 'tests/security/authz.test.ts' }];
  const probeResults: ProbeResultLike[] = [{ id: 'dast.headers.csp', passed: true, observed: 'CSP present with nonce.', requirementIds: ['V3.4.3'], expected: 'CSP header present' }];

  const manifestCtx = makeManifestCheckContext({ buildSpec: buildSpecFixture({ auth: true, ai: true }), testResults: [{ name: 'V6.2.1 rejects short passwords', ok: false }], probeResults });
  const manifestResults = await evaluateManifestControls(manifestFixture, manifestCtx);

  const aiReview: AiReviewResult = {
    performed: true,
    model: 'claude-opus-5',
    promptHash: 'hash-abc',
    assessments: [{ requirementId: 'C5.2.1', status: 'pass', confidence: 'high', rationale: 'Data access is scoped to req.user.', citations: [{ file: 'src/features/ai/index.ts', line: 3, verified: true }] }],
  };

  const findings = [finding()];
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
  };

  const compliance = evaluateCompliance({
    design,
    profile: clinicBookings,
    manifest: manifestFixture,
    manifestResults,
    findings,
    evidence: [],
    testResults,
    probeResults,
    aiReview,
    attestations: [],
    runMeta,
    knowledge,
    frameworks,
  });

  const provenance: Provenance = {
    reportSchemaVersion: '1.0.0',
    tool: 'SecureVibe 0.1.0',
    securevibeVersion: '0.1.0',
    templateVersion: '0.0.1',
    frameworkVersions: { asvs: frameworks.asvs.version, aisvs: frameworks.aisvs.version, sbd: frameworks.sbd.version },
    toolVersions: { node: '26.0.0' },
    runId: 'run_0001',
    projectId: 'p_fixture',
    generatedAt: NOW.toISOString(),
    mode: 'full',
    humanInvolvement: { summary: 'Design confirmed and build approved by Dr Lee Okafor.', buildApprovedAt: NOW.toISOString(), approvedBy: 'Dr Lee Okafor', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
    designProfileHash: design.profileHash,
    designHash: design.profileHash,
    codeTreeHash: 'sha256:abc123',
    generatedFiles: [],
    protectedFileHashes: {},
    sandbox: { mode: 'node-permission-model', note: 'network access is not restricted' },
  };

  const project: Project = {
    id: 'p_fixture',
    name: clinicBookings.app.name,
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
    profile: clinicBookings,
    profileHash: design.profileHash,
    wizardStep: 6,
    design,
    status: 'built',
    lastRunId: 'run_0001',
    runs: [],
    designStale: false,
    buildStale: false,
    appVersion: 1,
    attestations: [],
    findingDecisions: [],
  };

  const coverage: ToolCoverage[] = [
    { tool: 'sast', ran: true, covers: 'Static analysis of the generated TypeScript and EJS files.' },
    { tool: 'deps', ran: false, reason: 'offline', covers: 'Known-vulnerable dependency advisories.' },
  ];

  const run: PipelineRun = {
    id: 'run_0001',
    projectId: 'p_fixture',
    mode: 'full',
    startedAt: NOW.toISOString(),
    finishedAt: NOW.toISOString(),
    status: 'succeeded',
    stages: [
      { id: 'sast', status: 'passed', summary: 'No open findings above medium.', round: 0 },
      { id: 'deps', status: 'skipped', skippedReason: 'offline', summary: 'The dependency check needs an internet connection.', round: 0 },
      { id: 'unit-tests', status: 'passed', summary: '1 test passed.', details: { tests: testResults }, round: 0 },
      { id: 'dast', status: 'passed', summary: '1 probe passed.', details: { probes: probeResults }, round: 0 },
    ],
    findings,
    compliance,
    coverage,
    artifacts: [],
    fixRounds: 0,
    provenance,
    incomplete: false,
    approvedAt: NOW.toISOString(),
    approvedBy: 'Dr Lee Okafor',
  };

  return {
    project,
    design,
    profile: clinicBookings,
    run,
    compliance,
    findings,
    coverage,
    probeResults,
    testResults,
    provenance,
    knowledge,
    appDir,
    outDir,
    securevibeVersion: '0.1.0',
  };
}
