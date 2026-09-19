/**
 * Per-requirement evidence assembly (CONTRACTS §9.4, DESIGN §13.1): turns manifest control results, test results,
 * runtime probes, scanner findings, extra scanner evidence, the AI review and human attestations into the
 * `Evidence[]` / `openFindings` / `aiVerdict` / `attestation` bag that `compliance/status.ts` decides a status from.
 */
import type { Evidence, EvidenceType, NotVerifiedReason, StandardId, VerificationClass } from '@shared/compliance.js';
import { EVIDENCE_TIER } from '@shared/compliance.js';
import type { DesignArtifacts } from '@shared/design.js';
import { isOpen, type Confidence, type Finding } from '@shared/findings.js';
import type { RequirementMapping, TemplateControl, TemplateManifest } from '@shared/knowledge.js';
import type { StageResult } from '@shared/pipeline.js';
import type { Attestation, HumanCodeReview } from '@shared/project.js';
import type { StatusContext } from './status.js';
import type { AiReviewResult, ManifestControlResult, ProbeResultLike, RunMeta, TestResult } from './types.js';
import { EvidenceIds } from './evidence-ids.js';

export interface RequirementEvidenceCtx {
  standard: StandardId;
  manifest: TemplateManifest;
  manifestResults: ManifestControlResult[];
  testResults: TestResult[];
  probeResults: ProbeResultLike[];
  findings: Finding[];
  /** Extra scanner/config evidence: `requirementIds`, or the requirement id inside `ref` (see EvaluateInput.evidence). */
  extraEvidence: Evidence[];
  aiReview?: AiReviewResult;
  attestations: Attestation[];
  humanReview?: HumanCodeReview;
  runMeta: RunMeta;
  design: DesignArtifacts;
  ids: EvidenceIds;
  capturedAt: string;
}

export interface RequirementEvidenceResult {
  statusCtxPartial: Pick<StatusContext, 'evidence' | 'partialCoverage' | 'openFindings' | 'aiVerdict' | 'attestation'>;
  notVerifiedReason: NotVerifiedReason;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** True when `ref` mentions `id` as a whole token: "config:V13.2.3" mentions "V13.2.3", but does not also match a longer id that merely starts with it. */
export function refMentionsRequirement(ref: string, id: string): boolean {
  const re = new RegExp(`(^|[^0-9A-Za-z.])${escapeRegExp(id)}([^0-9A-Za-z.]|$)`);
  return re.test(ref);
}

/** True when a test name starts with `id` as a whole token ("V6.2.1 rejects…" matches "V6.2.1", not "V6.2.10"). */
export function testMatchesRequirement(name: string, id: string): boolean {
  // node:test reports nested names as "suite > test"; the id leads the test's own name.
  const own = name.split(' > ').at(-1) ?? name;
  const re = new RegExp(`^${escapeRegExp(id)}([^0-9A-Za-z.]|$)`);
  return re.test(own);
}

function controlMapping(control: TemplateControl, standard: StandardId, id: string): RequirementMapping | undefined {
  if (standard === 'asvs') return control.asvs.find((m) => m.id === id);
  if (standard === 'aisvs') return control.aisvs.find((m) => m.id === id);
  return undefined; // AISVS Appendix C ids are never mapped from template controls (process-level, not code-level)
}

function mkEvidence(
  ids: EvidenceIds,
  type: EvidenceType,
  ref: string,
  summary: string,
  passed: boolean,
  opts: { tool?: string; runId?: string; capturedAt?: string; producedBy?: string; aiReview?: Evidence['aiReview']; location?: Evidence['location'] } = {},
): Evidence {
  return {
    id: ids.next(),
    type,
    tier: EVIDENCE_TIER[type],
    ref,
    summary,
    passed,
    ...(opts.tool ? { tool: opts.tool } : {}),
    ...(opts.runId ? { runId: opts.runId } : {}),
    ...(opts.capturedAt ? { capturedAt: opts.capturedAt } : {}),
    ...(opts.producedBy ? { producedBy: opts.producedBy } : {}),
    ...(opts.aiReview ? { aiReview: opts.aiReview } : {}),
    ...(opts.location ? { location: opts.location } : {}),
  };
}

/** Manifest-control evidence: one item per control mapped to `id`, credited only when the control is expected and passed. */
function manifestControlEvidence(id: string, ctx: RequirementEvidenceCtx, partialCoverage: Set<string>): Evidence[] {
  const out: Evidence[] = [];
  for (const control of ctx.manifest.controls) {
    const mapping = controlMapping(control, ctx.standard, id);
    if (!mapping) continue;
    const result = ctx.manifestResults.find((r) => r.controlId === control.id);
    if (!result || !result.expected) continue; // not part of this build: silence, not a failure
    // A control that was not credited only because a check was skipped, or because it has no crediting check,
    // is unverified rather than failed: it adds no evidence either way.
    const actuallyFailed = result.checks.some((c) => !c.passed && !c.skippedReason);
    if (!result.passed && !actuallyFailed) continue;
    const e = mkEvidence(ctx.ids, 'template-control', control.id, `${mapping.proves}`, result.passed, {
      tool: 'securevibe-manifest',
      runId: ctx.runMeta.runId,
      capturedAt: ctx.capturedAt,
      producedBy: 'rules',
    });
    out.push(e);
    if (mapping.coverage === 'partial') partialCoverage.add(e.id);
  }
  return out;
}

/** Automated-test evidence: one item per test whose name starts with `id`. */
function testEvidence(id: string, ctx: RequirementEvidenceCtx): Evidence[] {
  return ctx.testResults
    .filter((t) => !t.skipped && testMatchesRequirement(t.name, id))
    .map((t) =>
      mkEvidence(ctx.ids, 'test', `test:${t.name}`, `Automated test "${t.name}" ${t.ok ? 'passed' : 'failed'}${t.detail ? `: ${t.detail}` : ''}.`, t.ok, {
        tool: 'node:test',
        runId: ctx.runMeta.runId,
        capturedAt: ctx.capturedAt,
        producedBy: 'rules',
        ...(t.file ? { location: { file: t.file } } : {}),
      }),
    );
}

/** Runtime-probe evidence: one item per probe whose `requirementIds` names `id`; probes that could not run are silent. */
function probeEvidence(id: string, ctx: RequirementEvidenceCtx): Evidence[] {
  // A failed probe whose finding was reviewed and marked a false positive is not evidence against the requirement.
  const falsePositive = new Set(ctx.findings.filter((f) => f.source === 'dast' && f.status === 'false-positive').map((f) => f.ruleId));
  return ctx.probeResults
    .filter((p) => p.passed !== null && (p.requirementIds ?? []).includes(id))
    .filter((p) => p.passed || !falsePositive.has(p.id))
    .map((p) =>
      mkEvidence(
        ctx.ids,
        'dast',
        `dast:${p.id}`,
        p.passed
          ? `Runtime probe "${p.id}" passed${p.observed ? `: ${p.observed}` : ''}.`
          : `Runtime probe "${p.id}" failed${p.expected ? ` (expected ${p.expected})` : ''}${p.observed ? `: ${p.observed}` : ''}.`,
        p.passed as boolean,
        { tool: 'securevibe-dast', runId: ctx.runMeta.runId, capturedAt: ctx.capturedAt, producedBy: 'rules', ...(p.endpoint ? { location: { file: p.endpoint } } : {}) },
      ),
    );
}

/** Extra scanner/config evidence handed to the engine directly, matched by scanning its `ref` for the id. */
function extraEvidenceFor(id: string, ctx: RequirementEvidenceCtx, partialCoverage: Set<string>): Evidence[] {
  // Either the evidence names this requirement outright, or its ref mentions it (older producers).
  const matches = ctx.extraEvidence.filter((e) => e.requirementIds?.includes(id) || refMentionsRequirement(e.ref, id));
  // Extra template-control evidence from other producers may already record partial coverage in its summary;
  // nothing else to do here — it is not double-counted against the manifest's own controls (different refs).
  return matches;
}

/** Scanner-clean evidence: a positive "no issues detected" item when the verification class rests on rule absence. */
function scannerCleanEvidence(id: string, ctx: RequirementEvidenceCtx, hasOpenFinding: boolean): Evidence[] {
  if (hasOpenFinding) return [];
  const ruleIds = new Set(
    ctx.findings
      .filter((f) => f.source === 'sast' && ((ctx.standard === 'asvs' ? f.mappings.asvs : f.mappings.aisvs) ?? []).includes(id))
      .map((f) => f.ruleId),
  );
  const summary = ruleIds.size > 0 ? `No open issues were detected by the ${ruleIds.size} static rule(s) that cover this requirement.` : 'No issues were detected by the static analysis rules that cover this requirement.';
  return [mkEvidence(ctx.ids, 'scanner', `scanner-clean:${id}`, summary, true, { tool: 'securevibe-sast', runId: ctx.runMeta.runId, capturedAt: ctx.capturedAt, producedBy: 'rules' })];
}

interface AiSignal {
  verdict?: 'pass' | 'partial' | 'fail';
  citationUnverified?: boolean;
  lowConfidence?: boolean;
}

function aiReviewEvidence(id: string, ctx: RequirementEvidenceCtx): { evidence: Evidence[]; signal: AiSignal } {
  const review = ctx.aiReview;
  if (!review || !review.performed) return { evidence: [], signal: {} };
  const assessment = review.assessments.find((a) => a.requirementId === id);
  if (!assessment) return { evidence: [], signal: {} };
  const hasCitations = assessment.citations.length > 0;
  const allVerified = hasCitations && assessment.citations.every((c) => c.verified);
  const confidenceOk = assessment.confidence !== 'low';
  if (!allVerified) return { evidence: [], signal: { citationUnverified: true } };
  if (!confidenceOk) return { evidence: [], signal: { lowConfidence: true } };
  if (assessment.status === 'unknown' || assessment.status === 'not-applicable') return { evidence: [], signal: {} };
  const verdict = assessment.status;
  const passed = verdict === 'pass';
  const evidence = [
    mkEvidence(ctx.ids, 'ai-review', `ai-review:${id}`, assessment.rationale, passed, {
      tool: review.model ?? 'claude',
      runId: ctx.runMeta.runId,
      capturedAt: ctx.capturedAt,
      producedBy: review.model ?? 'claude',
      aiReview: {
        model: review.model ?? 'unknown',
        promptHash: review.promptHash ?? '',
        confidence: assessment.confidence,
        citationVerified: true,
        citedFiles: [...new Set(assessment.citations.map((c) => c.file))],
      },
      ...(assessment.citations[0] ? { location: { file: assessment.citations[0].file, ...(assessment.citations[0].line !== undefined ? { line: assessment.citations[0].line } : {}) } } : {}),
    }),
  ];
  return { evidence, signal: { verdict } };
}

function attestationEvidence(id: string, ctx: RequirementEvidenceCtx): { evidence: Evidence[]; attestation?: Attestation } {
  const attestation = ctx.attestations.find((a) => a.requirementId === id && a.standard === ctx.standard);
  if (!attestation) return { evidence: [] };
  // "Not sure" is neither a pass nor a fail: the requirement stays unverified (the rationale mentions the answer).
  if (attestation.result === 'not-sure') return { evidence: [], attestation };
  const passed = attestation.result === 'yes';
  const evidence = [
    mkEvidence(ctx.ids, 'manual', `manual:attestation:${attestation.id}`, attestation.note || `${attestation.attestedBy} attested "${attestation.result}".`, passed, {
      tool: 'human-attestation',
      capturedAt: attestation.attestedAt,
      producedBy: attestation.attestedBy,
    }),
  ];
  return { evidence, attestation };
}

/** AISVS Appendix C AC.4.1 / AC.4.4: reported as failing until a named person records a code review (DESIGN §13.4). */
function humanCodeReviewEvidence(id: string, ctx: RequirementEvidenceCtx): Evidence[] {
  if (id !== 'AC.4.1' && id !== 'AC.4.4') return [];
  const hr = ctx.humanReview;
  const performed = hr !== undefined && hr.reviewedBy.trim().length > 0 && (id !== 'AC.4.4' || hr.filesReviewed.length > 0);
  const summary = performed
    ? `${hr!.reviewedBy} reviewed ${hr!.filesReviewed.length} security-critical file(s) on ${hr!.reviewedAt.slice(0, 10)}.`
    : 'No named person has recorded a review of the security-critical files for this build yet.';
  return [mkEvidence(ctx.ids, 'manual', 'manual:human-code-review', summary, performed, { tool: 'human-code-review', producedBy: hr?.reviewedBy ?? 'none' })];
}

/** Process-level facts about this build used as evidence for AISVS Appendix C requirements outside the manifest. */
function appendixCFacts(id: string, runMeta: RunMeta, design: DesignArtifacts): { type: EvidenceType; passed: boolean; summary: string }[] {
  switch (id) {
    case 'AC.1.1':
      return [{ type: 'design', passed: true, summary: "SecureVibe's documented AI-usage policy (docs/AI-USAGE-POLICY.md in the SecureVibe folder) says what the AI code generator and reviewer may and may not do; it applies to every build." }];
    case 'AC.2.1':
      return [{ type: 'design', passed: design.threatModel !== undefined, summary: design.threatModel ? `A STRIDE threat model covering ${design.threatModel.threats.length} threat(s) was generated for this design.` : 'No threat model was generated for this design.' }];
    case 'AC.3.1':
    case 'AC.3.2':
    case 'AC.3.3':
    case 'AC.3.4':
    case 'AC.3.5':
      return runMeta.screeningPerformed === undefined
        ? []
        : [
            {
              type: 'config',
              passed: runMeta.screeningPerformed,
              summary: runMeta.screeningPerformed
                ? `Untrusted free text was screened for prompt-injection patterns before it reached the model (${runMeta.screeningEvents ?? 0} screening event(s) recorded for this run).`
                : 'Untrusted-text screening did not run for this build.',
            },
          ];
    case 'AC.4.2':
    case 'AC.4.3':
      return [
        {
          type: 'design',
          passed: design.peerReview?.performedBy === 'claude' || design.peerReview?.performedBy === 'rules',
          summary: design.peerReview
            ? `The design's second opinion is labelled as performed by "${design.peerReview.performedBy}"${design.peerReview.model ? ` (${design.peerReview.model})` : ''}; ${design.peerReview.suggestions.filter((s) => s.accepted === true).length} suggestion(s) were accepted and recorded.`
            : 'No second-opinion review is recorded for this design.',
        },
      ];
    case 'AC.5.1':
      return runMeta.auditLogPresent === undefined
        ? []
        : [{ type: 'config', passed: runMeta.auditLogPresent, summary: runMeta.auditLogPresent ? 'Every AI call for this run was logged with a correlation id, purpose, model and token usage (llm-audit.jsonl).' : 'The AI-call audit log was not found for this run.' }];
    case 'AC.7.1':
    case 'AC.7.2':
    case 'AC.10.1':
    case 'AC.10.2':
      return runMeta.provenance === undefined
        ? []
        : [
            { type: 'config', passed: true, summary: `Provenance metadata was written for this build (run ${runMeta.provenance.runId}, generated ${runMeta.provenance.generatedAt}).` },
            {
              type: 'config',
              passed: Boolean(runMeta.provenance.codeTreeHash),
              summary: runMeta.provenance.codeTreeHash
                ? 'A hash of the exact source tree that was assessed is recorded in the provenance file, so the reviewed code can be verified later.'
                : 'No hash of the assessed source tree is recorded.',
            },
          ];
    case 'AC.8.1':
      // Approval gates the code generator; a verify-only run generates nothing, so there is nothing to approve.
      if (runMeta.mode === 'verify-only') return [];
      return [
        { type: 'config', passed: Boolean(runMeta.approvedBy), summary: runMeta.approvedBy ? `A human ("${runMeta.approvedBy}") approved this build before the code generator ran.` : 'No named approver is recorded for this build.' },
        { type: 'config', passed: Boolean(runMeta.approvedAt), summary: runMeta.approvedAt ? `Approval was recorded on ${runMeta.approvedAt.slice(0, 10)}.` : 'No approval timestamp is recorded for this build.' },
      ];
    case 'AC.11.3':
      return runMeta.protectedHashesVerified === undefined
        ? []
        : [
            {
              type: 'config',
              passed: runMeta.protectedHashesVerified,
              summary: runMeta.protectedHashesVerified
                ? 'The generation agent could only write inside the confined project folder, and the protected security files were hash-verified unchanged after the build.'
                : 'The protected security files did not hash-verify as unchanged after the build.',
            },
          ];
    default:
      return [];
  }
}

function appendixCEvidence(id: string, ctx: RequirementEvidenceCtx): Evidence[] {
  return appendixCFacts(id, ctx.runMeta, ctx.design).map((f) =>
    mkEvidence(ctx.ids, f.type, `run:${id}`, f.summary, f.passed, { tool: 'securevibe-pipeline', runId: ctx.runMeta.runId, capturedAt: ctx.capturedAt, producedBy: 'rules' }),
  );
}

const SKIP_KEYWORD_REASON: [RegExp, NotVerifiedReason][] = [
  [/offline/i, 'check-skipped-offline'],
  [/depend/i, 'check-skipped-dependencies-missing'],
];

/** The most informative reason any relevant automated stage did not produce a result, from the run's stage list. */
function worstSkipReason(stages: StageResult[] | undefined): NotVerifiedReason | undefined {
  if (!stages) return undefined;
  const relevantStageIds = new Set(['unit-tests', 'sast', 'secrets', 'deps', 'config', 'dast', 'ai-review']);
  const relevant = stages.filter((s) => relevantStageIds.has(s.id));
  const skipped = relevant.filter((s) => s.status === 'skipped');
  for (const s of skipped) {
    for (const [re, reason] of SKIP_KEYWORD_REASON) if (s.skippedReason && re.test(s.skippedReason)) return reason;
  }
  if (skipped.length > 0) return 'check-skipped-dependencies-missing';
  if (relevant.some((s) => s.status === 'failed')) return 'check-errored';
  return undefined;
}

function chooseNotVerifiedReason(
  verificationClass: VerificationClass,
  ctx: RequirementEvidenceCtx,
  aiSignal: AiSignal,
): NotVerifiedReason {
  if (verificationClass === 'manual-only') return 'requires-human';
  if (verificationClass === 'deployment-time') return 'requires-deployment';
  if (aiSignal.citationUnverified) return 'citation-unverified';
  if (aiSignal.lowConfidence) return 'low-confidence';
  if (ctx.aiReview && ctx.aiReview.declined) return 'model-declined';
  const skip = worstSkipReason(ctx.runMeta.stages);
  if (skip) return skip;
  if (ctx.runMeta.provider === null && verificationClass === 'ai-assistable') return 'demo-mode';
  return 'no-check-available';
}

export function buildRequirementEvidence(id: string, verificationClass: VerificationClass, ctx: RequirementEvidenceCtx): RequirementEvidenceResult {
  const partialCoverage = new Set<string>();
  const evidence: Evidence[] = [
    ...manifestControlEvidence(id, ctx, partialCoverage),
    ...testEvidence(id, ctx),
    ...probeEvidence(id, ctx),
    ...extraEvidenceFor(id, ctx, partialCoverage),
  ];

  const openFindings = ctx.findings.filter((f) => isOpen(f) && ((ctx.standard === 'asvs' ? f.mappings.asvs : ctx.standard === 'aisvs' ? f.mappings.aisvs : []) ?? []).includes(id));

  if (verificationClass === 'scanner-clean') evidence.push(...scannerCleanEvidence(id, ctx, openFindings.length > 0));

  const { evidence: aiEvidence, signal: aiSignal } = aiReviewEvidence(id, ctx);
  evidence.push(...aiEvidence);

  const { evidence: attEvidence, attestation } = attestationEvidence(id, ctx);
  evidence.push(...attEvidence);

  evidence.push(...humanCodeReviewEvidence(id, ctx));
  if (ctx.standard === 'aisvs-appendix-c') evidence.push(...appendixCEvidence(id, ctx));

  const notVerifiedReason = chooseNotVerifiedReason(verificationClass, ctx, aiSignal);

  return {
    statusCtxPartial: { evidence, partialCoverage, openFindings, ...(aiSignal.verdict ? { aiVerdict: aiSignal.verdict } : {}), ...(attestation ? { attestation } : {}) },
    notVerifiedReason,
  };
}

export type { Confidence };
