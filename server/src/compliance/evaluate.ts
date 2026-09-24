/**
 * The compliance engine's entry point (CONTRACTS §9.4): turns manifest checks, tests, runtime probes, scanner
 * findings, the AI review, attestations and human review into a full `ComplianceResult` — SbD, ASVS, AISVS
 * (when applicable), Appendix C, traceability, recommendations, manual-verification list and the overall verdict.
 *
 * Every status is decided by `compliance/status.ts` from evidence assembled by `compliance/evidence.ts`; this
 * module only wires ids to evidence, then aggregates.
 */
import type { ComplianceResult, RequirementResult, RequirementStatus, StandardId, StandardSummary } from '@shared/compliance.js';
import { emptyCounts } from '@shared/compliance.js';
import { isOpen, type Finding } from '@shared/findings.js';
import type { DesignProfile } from '@shared/profile.js';
import { deploymentNoteFor, loadFrameworks, verificationClassFor, type Frameworks } from '../frameworks/index.js';
import type { Knowledge } from '../frameworks/knowledge.js';
import { buildRequirementEvidence, type RequirementEvidenceCtx } from './evidence.js';
import { EvidenceIds } from './evidence-ids.js';
import { buildRecommendations } from './recommendations.js';
import { evaluateSbd } from './sbd.js';
import { contradicts, decideStatus, type StatusContext } from './status.js';
import { computeRating, summarizeStandard } from './summaries.js';
import { buildTraceability } from './traceability.js';
import type { EvaluateInput } from './types.js';

const REPORT_SCHEMA_VERSION = '1.0.0';

const QUALITY_RANK: Record<RequirementStatus, number> = {
  fail: 0,
  'not-verified': 1,
  documented: 1,
  'ai-assessed': 1,
  attested: 1,
  partial: 2,
  pass: 3,
  'not-applicable': -1,
  'out-of-level': -1,
};

function assessedByFrom(evidence: RequirementResult['evidence'], hasAttestation: boolean): RequirementResult['assessedBy'] {
  const out = new Set<'rules' | 'ai-review' | 'manual'>();
  for (const e of evidence) {
    if (e.type === 'ai-review') out.add('ai-review');
    else if (e.type === 'manual') out.add('manual');
    else out.add('rules');
  }
  if (hasAttestation) out.add('manual');
  if (out.size === 0) out.add('rules');
  return [...out];
}

function remediationFor(status: RequirementStatus, openFindings: Finding[], manualSteps: string[] | undefined): string | undefined {
  if (status !== 'fail' && status !== 'partial') return undefined;
  const contradicting = openFindings.filter(contradicts);
  if (contradicting.length > 0) return contradicting.map((f) => `${f.id}: ${f.remediation.summary}`).join(' ');
  if (manualSteps && manualSteps.length > 0) return manualSteps.join(' ');
  return 'Ask a developer to review this requirement; no automated fix is available for it yet.';
}

interface StandardEvalResult {
  summary: StandardSummary;
  results: RequirementResult[];
}

function evaluateStandard(
  standardId: StandardId,
  name: string,
  version: string,
  targetLevel: number,
  targetLevelRule: string,
  applicable: string[],
  notApplicable: { id: string; reason: string }[],
  outOfLevel: string[],
  frameworks: Frameworks,
  knowledge: Knowledge,
  ctxBase: Omit<RequirementEvidenceCtx, 'standard'>,
  findings: Finding[],
): StandardEvalResult {
  const results: RequirementResult[] = [];

  for (const id of outOfLevel) {
    const info = frameworks.getRequirement(id);
    if (!info) continue;
    results.push({
      id,
      standard: standardId,
      chapterId: info.chapterId,
      chapterName: info.chapterName,
      sectionId: info.sectionId,
      sectionName: info.sectionName,
      description: info.description,
      level: info.level,
      status: 'out-of-level',
      verificationClass: verificationClassFor(id, knowledge),
      evidence: [],
      rationale: `This requirement belongs to verification level ${info.level}, above this app's target level ${targetLevel}.`,
      findingIds: [],
      assessedBy: ['rules'],
    });
  }

  for (const na of notApplicable) {
    const info = frameworks.getRequirement(na.id);
    if (!info) continue;
    results.push({
      id: na.id,
      standard: standardId,
      chapterId: info.chapterId,
      chapterName: info.chapterName,
      sectionId: info.sectionId,
      sectionName: info.sectionName,
      description: info.description,
      level: info.level,
      status: 'not-applicable',
      verificationClass: verificationClassFor(na.id, knowledge),
      notApplicableReason: na.reason,
      evidence: [],
      rationale: na.reason,
      findingIds: [],
      assessedBy: ['rules'],
    });
  }

  for (const id of applicable) {
    const info = frameworks.getRequirement(id);
    if (!info) continue;
    const verificationClass = verificationClassFor(id, knowledge);
    const ctx: RequirementEvidenceCtx = { ...ctxBase, standard: standardId };
    const { statusCtxPartial, notVerifiedReason } = buildRequirementEvidence(id, verificationClass, ctx);

    const statusCtx: StatusContext = {
      verificationClass,
      manualOnly: verificationClass === 'manual-only',
      notVerifiedReason,
      ...statusCtxPartial,
    };
    const decision = decideStatus(statusCtx);
    const plain = knowledge.requirementsPlain[id];
    const remediation = remediationFor(decision.status, statusCtxPartial.openFindings, plain?.manual?.steps);

    results.push({
      id,
      standard: standardId,
      chapterId: info.chapterId,
      chapterName: info.chapterName,
      sectionId: info.sectionId,
      sectionName: info.sectionName,
      description: info.description,
      level: info.level,
      status: decision.status,
      verificationClass,
      ...(decision.notVerifiedReason ? { notVerifiedReason: decision.notVerifiedReason } : {}),
      evidence: statusCtxPartial.evidence,
      rationale: decision.rationale,
      findingIds: statusCtxPartial.openFindings.map((f) => f.id),
      ...(remediation ? { remediation } : {}),
      assessedBy: assessedByFrom(statusCtxPartial.evidence, statusCtxPartial.attestation !== undefined),
      ...(plain?.plain ? { plainLanguage: plain.plain } : {}),
      ...(plain?.manual ? { manualVerification: plain.manual } : {}),
      ...(deploymentNoteFor(id, knowledge) ? { deploymentNote: deploymentNoteFor(id, knowledge) } : {}),
    });
  }

  results.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
  const summary = summarizeStandard(standardId, name, version, targetLevel, targetLevelRule, results, findings);
  return { summary, results };
}

function skippedStagesText(stages: EvaluateInput['runMeta']['stages']): string | undefined {
  const skipped = (stages ?? []).filter((s) => s.status === 'skipped' && s.skippedReason);
  if (skipped.length === 0) return undefined;
  return `Some checks were skipped this run: ${skipped.map((s) => `${s.id} (${s.skippedReason})`).join('; ')}.`;
}

function methodologyText(input: EvaluateInput): string {
  const sandbox =
    input.runMeta.sandbox?.note ??
    "Generated code runs with the user's OS privileges under Node's permission model (file system restricted to the project folder); network access is not restricted.";
  const aiPart = input.aiReview?.performed
    ? `An AI code review checked ${input.aiReview.assessments.length} requirement(s) against the code and cited a file and line for each finding; citations were verified against the actual files before being counted as evidence.`
    : 'No AI code review ran for this build (no AI key configured, or preview mode); requirements that would need it are shown as "Not verified".';
  return [
    'SecureVibe checked this application with automated tests, runtime probes against the running app, static code analysis, dependency and secret scanning, and configuration checks.',
    aiPart,
    sandbox,
    'No independent human security review was performed unless it is recorded in the human sign-off section below.',
    'This is an automated and AI-assisted assessment. It is not a certification and does not replace a professional security review.',
  ].join(' ');
}

function limitationsFor(input: EvaluateInput): string[] {
  const out: string[] = [];
  out.push(
    input.runMeta.sandbox?.note ??
      "Generated code and its tests run under Node's permission model restricted to the project folder; network access is not restricted.",
  );
  if (input.runMeta.provider === null) {
    out.push(
      'This was a preview build: the AI did not customize the code and did not perform a review, so more requirements than usual rely on automated checks alone or are marked "Not verified".',
    );
  }
  if (input.aiReview?.performed) {
    out.push(`The AI review covered ${input.aiReview.assessments.length} of the requirements it was asked about; every citation it made was checked against the actual file before being counted.`);
    if ((input.aiReview.unverifiedCitations ?? 0) > 0) {
      out.push(`${input.aiReview.unverifiedCitations} AI review citation(s) could not be found at the place cited and were discarded.`);
    }
  }
  const skipped = skippedStagesText(input.runMeta.stages);
  if (skipped) out.push(skipped);
  out.push('No independent, professional application-security review of this code has been performed.');
  return out;
}

/**
 * Naming the blocker matters more than counting it. "1 urgent security issue need fixing first, see the top
 * actions below" sent an owner to a list of five actions, none of which was the blocker: a finding SecureVibe
 * fixes itself never becomes an action, because actions are things a person does. So the sentence pointed at a
 * place the answer could not be. It says which issue now, and sends the reader where that issue really is.
 */
function canIUseIt(
  deploymentTarget: DesignProfile['deployment']['target'] | undefined,
  p1Findings: Finding[],
  topActionCount: number,
  criticalNo: string[] = [],
): string {
  if (p1Findings.length > 0) {
    const named = p1Findings.slice(0, 2).map((f) => `"${f.title}"`).join(' and ');
    const rest = p1Findings.length > 2 ? `, and ${p1Findings.length - 2} more` : '';
    return p1Findings.length === 1
      ? `Not yet — one urgent security issue needs fixing first: ${named}. It is under "What we found" below, with the evidence behind it.`
      : `Not yet — ${p1Findings.length} urgent security issues need fixing first, starting with ${named}${rest}. They are under "What we found" below, with the evidence behind each one.`;
  }
  if (deploymentTarget === 'local-only' || deploymentTarget === undefined) {
    // With no urgent finding, "At risk" comes only from unmet Secure by Design critical controls; say so, so the
    // red rating and the "yes" do not read as a contradiction.
    if (criticalNo.length > 0) {
      return `Yes, on this computer. The "At risk" rating is because ${criticalNo.length === 1 ? 'a critical Secure by Design control' : `${criticalNo.length} critical Secure by Design controls`} (${criticalNo.join(', ')}) ${criticalNo.length === 1 ? 'is' : 'are'} not met yet. The matching actions below say what to do and when.`;
    }
    return topActionCount === 0
      ? 'Yes — ready to use on this computer.'
      : `Yes — ready to use on this computer, with ${topActionCount} action${topActionCount === 1 ? '' : 's'} below when you have time.`;
  }
  return 'Almost — finish the "Going online safely" checklist and the action(s) below before sharing it beyond this computer.';
}

export function evaluateCompliance(input: EvaluateInput): ComplianceResult {
  const frameworks = input.frameworks ?? loadFrameworks();
  const { design, knowledge } = input;
  const applicability = design.applicability;
  const ids = new EvidenceIds('E');
  const capturedAt = input.runMeta.generatedAt ?? new Date().toISOString();

  const ctxBase: Omit<RequirementEvidenceCtx, 'standard'> = {
    manifest: input.manifest,
    manifestResults: input.manifestResults,
    testResults: input.testResults,
    probeResults: input.probeResults,
    findings: input.findings,
    extraEvidence: input.evidence,
    aiReview: input.aiReview,
    attestations: input.attestations,
    humanReview: input.humanReview,
    runMeta: input.runMeta,
    design,
    ids,
    capturedAt,
  };

  const asvsEval = evaluateStandard(
    'asvs',
    frameworks.asvs.name,
    frameworks.asvs.version,
    applicability.targetLevel,
    applicability.targetLevelRule,
    applicability.asvs.applicable,
    applicability.asvs.notApplicable,
    applicability.asvs.outOfLevel,
    frameworks,
    knowledge,
    ctxBase,
    input.findings,
  );

  let aisvsEval: StandardEvalResult | undefined;
  if (applicability.aisvs.enabled) {
    aisvsEval = evaluateStandard(
      'aisvs',
      frameworks.aisvs.name,
      frameworks.aisvs.version,
      applicability.targetLevel,
      applicability.targetLevelRule,
      applicability.aisvs.applicable,
      applicability.aisvs.notApplicable,
      applicability.aisvs.outOfLevel,
      frameworks,
      knowledge,
      ctxBase,
      input.findings,
    );
  }

  const appendixCEval = evaluateStandard(
    'aisvs-appendix-c',
    frameworks.appendixC.name,
    frameworks.appendixC.version,
    applicability.targetLevel,
    applicability.targetLevelRule,
    applicability.appendixC.applicable,
    applicability.appendixC.notApplicable,
    applicability.appendixC.outOfLevel,
    frameworks,
    knowledge,
    ctxBase,
    input.findings,
  );

  const sbd = evaluateSbd({
    design,
    sbdRules: knowledge.sbdRules,
    sbd: frameworks.sbd,
    manifestResults: input.manifestResults,
    attestations: input.attestations,
    humanReview: input.humanReview,
    runMeta: input.runMeta,
  });

  const requirementStatus = new Map<string, RequirementStatus>();
  for (const r of [...asvsEval.results, ...(aisvsEval?.results ?? [])]) requirementStatus.set(r.id, r.status);
  const traceability = buildTraceability(design, input.manifest, requirementStatus, sbd.entries);

  const allAppResults = [...asvsEval.results, ...(aisvsEval?.results ?? [])];
  const recommendations = buildRecommendations(allAppResults, sbd.entries, input.findings);

  const manualVerification = [...allAppResults, ...appendixCEval.results]
    .filter((r) => r.manualVerification && r.status !== 'pass' && r.status !== 'not-applicable' && r.status !== 'out-of-level')
    .map((r) => ({ requirementId: r.id, standard: r.standard, manual: r.manualVerification! }));

  const humanReview: ComplianceResult['humanReview'] = input.humanReview
    ? {
        performed: input.humanReview.reviewedBy.trim().length > 0,
        reviewedBy: input.humanReview.reviewedBy,
        reviewedAt: input.humanReview.reviewedAt,
        filesReviewed: input.humanReview.filesReviewed,
        ...(input.humanReview.note ? { note: input.humanReview.note } : {}),
      }
    : { performed: false, filesReviewed: [] };

  let changesSincePrevious: ComplianceResult['changesSincePrevious'];
  if (input.previous) {
    const prevStatus = new Map<string, RequirementStatus>();
    for (const r of input.previous.asvs.results) prevStatus.set(r.id, r.status);
    for (const r of input.previous.aisvs?.results ?? []) prevStatus.set(r.id, r.status);
    for (const r of input.previous.appendixC?.results ?? []) prevStatus.set(r.id, r.status);
    const improved: string[] = [];
    const regressed: string[] = [];
    for (const r of [...allAppResults, ...appendixCEval.results]) {
      const prev = prevStatus.get(r.id);
      if (prev === undefined) continue;
      const before = QUALITY_RANK[prev];
      const after = QUALITY_RANK[r.status];
      if (before < 0 || after < 0) continue;
      if (after > before) improved.push(r.id);
      else if (after < before) regressed.push(r.id);
    }
    const prevFindings = input.previousFindings ?? [];
    const currentOpenFingerprints = new Set(input.findings.filter(isOpen).map((f) => f.fingerprint));
    const prevOpenFingerprints = new Set(prevFindings.filter(isOpen).map((f) => f.fingerprint));
    const newFindings = [...currentOpenFingerprints].filter((fp) => !prevOpenFingerprints.has(fp)).length;
    const fixedFindings = [...prevOpenFingerprints].filter((fp) => !currentOpenFingerprints.has(fp)).length;
    changesSincePrevious = { improved, regressed, newFindings, fixedFindings };
  }

  const p1Findings = input.findings.filter((f) => isOpen(f) && f.priority === 'P1');
  const p1Count = p1Findings.length;
  const overallCounts = allAppResults.reduce((acc, r) => {
    acc[r.status]++;
    return acc;
  }, emptyCounts());
  const overallApplicable = allAppResults.filter((r) => r.status !== 'not-applicable' && r.status !== 'out-of-level').length;
  const { rating: overallRating, ratingReason: overallRatingReason } = computeRating(
    overallCounts,
    overallApplicable,
    p1Count > 0,
    aisvsEval ? 'ASVS and AISVS' : 'ASVS',
    sbd.criticalNo,
  );
  /**
   * The headline says what was found, or says that nothing was looked at — never the first dressed as a score.
   *
   * "0 of 106 applicable requirements verified passing" is arithmetically true of an application whose code was
   * never read, and it is read by every person who sees it as *this app failed 106 requirements*. On
   * 20 September 2026 that sentence was printed about a Python app after the scanners had read one JavaScript
   * file. A requirement that was not assessed is not a failed one, for the same reason a scan that did not run
   * is not a clean result.
   */
  const scored = aisvsEval
    ? `${asvsEval.summary.counts.pass} of ${asvsEval.summary.applicableCount} applicable Level ${asvsEval.summary.targetLevel} ASVS requirements verified passing; ${aisvsEval.summary.counts.pass} of ${aisvsEval.summary.applicableCount} applicable AISVS requirements verified passing.`
    : `${asvsEval.summary.counts.pass} of ${asvsEval.summary.applicableCount} applicable Level ${asvsEval.summary.targetLevel} ASVS requirements verified passing.`;
  const coverage = input.codeCoverage;

  /**
   * The second way a score can be a verdict nobody earned, and the one the first fix did not cover.
   *
   * Strong evidence in this model means the application was *run*: a test executed, a live request refused.
   * SecureVibe never runs an app it did not build, so for an uploaded app the `unit-tests` and `dast` stages
   * are skipped and no strong evidence can exist at any price. The requirements that would have been verified
   * by them come out `not-verified`, the pass count comes out at or near zero, and the headline then says
   * "0 of 149 applicable requirements verified passing" about code that verified 104 of 159 an hour earlier
   * through the other door.
   *
   * Every number in that sentence is right and the sentence is false, which is the same failure as scoring an
   * app whose code was never read. The first fix guarded whether the code could be *read*; readability was
   * never the constraint here — Arm B was 151 files of 151 readable. What was missing was the evidence, and
   * that is what this looks at.
   */
  const unrunStages = (input.runMeta.stages ?? [])
    .filter((s) => (s.id === 'unit-tests' || s.id === 'dast') && s.status === 'skipped')
    .map((s) => s.id);
  const counts = asvsEval.summary.counts;
  const notVerified = counts['not-verified'] ?? 0;
  const otherEvidence = [
    (counts['ai-assessed'] ?? 0) > 0 ? `${counts['ai-assessed']} assessed by the AI review only` : '',
    (counts.partial ?? 0) > 0 ? `${counts.partial} partly met` : '',
    (counts.fail ?? 0) > 0 ? `${counts.fail} not met` : '',
  ].filter(Boolean);

  const headline =
    coverage && !coverage.assessable
      ? `Not assessed: ${coverage.summary} Without reading the code, SecureVibe cannot say whether this app meets the ${asvsEval.summary.applicableCount} requirements that apply to it, so it does not score them. Anything found below is real; what is absent has not been checked.`
      : unrunStages.length > 0 && notVerified > 0
        ? `${scored} That is not a verdict on the app: ${notVerified} of the ${asvsEval.summary.applicableCount} could not be assessed at all, because SecureVibe does not run an application it did not build — so this app's own tests and live checks, the only evidence that can verify them, never happened.${
            otherEvidence.length > 0 ? ` Of the rest, ${otherEvidence.join(', ')}.` : ''
          }`
        : coverage && coverage.unreadLanguages.length > 0
          ? `${scored} ${coverage.summary}`
          : scored;

  const recTop5 = recommendations.slice(0, 5);
  const deploymentTarget = input.profile?.deployment.target ?? input.runMeta.deploymentTarget;

  return {
    reportSchemaVersion: REPORT_SCHEMA_VERSION,
    generatedAt: capturedAt,
    runId: input.runMeta.runId,
    ...(input.runMeta.previousRunId ? { previousRunId: input.runMeta.previousRunId } : {}),
    sbd,
    ...(input.codeCoverage ? { codeCoverage: input.codeCoverage } : {}),
    asvs: { summary: asvsEval.summary, results: asvsEval.results },
    ...(aisvsEval ? { aisvs: { summary: aisvsEval.summary, results: aisvsEval.results } } : {}),
    appendixC: { summary: appendixCEval.summary, results: appendixCEval.results },
    traceability,
    recommendations,
    manualVerification,
    humanReview,
    methodology: methodologyText(input),
    limitations: limitationsFor(input),
    ...(changesSincePrevious ? { changesSincePrevious } : {}),
    overall: {
      rating: overallRating,
      ratingReason: overallRatingReason,
      headline,
      canIUseIt: canIUseIt(deploymentTarget, p1Findings, recTop5.length, sbd.criticalNo),
      topActions: recTop5,
    },
  };
}
