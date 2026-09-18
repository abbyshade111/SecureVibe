/**
 * The per-requirement status algorithm (CONTRACTS §9.4, DESIGN §13.1). Pure: evidence in, decision out.
 *
 * Order: manual-only → attested / fail (human said no) / not-verified;
 *        failing strong or medium evidence, or an open mapped finding with confidence >= medium → fail
 *          (partial when a strong check also passed);
 *        >= 1 strong pass or >= 2 medium pass → pass (partial when only partial-coverage controls carry it);
 *        1 medium pass → partial ("single static check");
 *        AI review (verified citation, confidence >= medium) says partly met → partial;
 *        only weak evidence: attestation → attested; AI pass → ai-assessed; generated document → documented;
 *        otherwise not-verified with a reason from the run context.
 */
import type { Evidence, NotVerifiedReason, RequirementStatus, VerificationClass } from '@shared/compliance.js';
import { isOpen, type Finding } from '@shared/findings.js';
import type { Attestation } from '@shared/project.js';

export interface StatusContext {
  verificationClass: VerificationClass;
  manualOnly: boolean;
  evidence: Evidence[];
  /** Ids of template-control evidence whose control covers the requirement only partly. */
  partialCoverage: ReadonlySet<string>;
  /** Open findings mapped to the requirement, any confidence. */
  openFindings: Finding[];
  /** Verdict of the AI review when its citation was verified and its confidence is at least medium. */
  aiVerdict?: 'pass' | 'partial' | 'fail';
  attestation?: Attestation;
  /** Reason to report when nothing could verify the requirement. */
  notVerifiedReason: NotVerifiedReason;
}

export interface StatusDecision {
  status: RequirementStatus;
  rationale: string;
  notVerifiedReason?: NotVerifiedReason;
}

/**
 * A finding contradicts a requirement when it is open, more than informational, not low-confidence and (for AI
 * findings) its citation was verified.
 */
export function contradicts(f: Finding): boolean {
  if (!isOpen(f)) return false;
  if (f.severity === 'info') return false;
  if (f.confidence === 'low') return false;
  if (f.source === 'ai-review' && f.citationVerified !== true) return false;
  return true;
}

/** Why a person-only check failed: an explicit "no" from someone, or the failing manual record's own words. */
function manualFailText(ctx: StatusContext, manualFail: Evidence[]): string {
  if (ctx.attestation?.result === 'no') return `${ctx.attestation.attestedBy} answered that it is not in place`;
  const summary = manualFail[0]?.summary.replace(/\.$/, '');
  return summary ? `the record says: ${summary.charAt(0).toLowerCase()}${summary.slice(1)}` : 'a reviewer answered that it is not in place';
}

function plural(n: number, singular: string, pluralWord = `${singular}s`): string {
  return `${n} ${n === 1 ? singular : pluralWord}`;
}

/** "2 tests, 1 runtime probe and 1 template control" for a list of evidence. */
export function describeEvidence(items: Evidence[]): string {
  const counts = new Map<string, number>();
  const label: Record<Evidence['type'], [string, string]> = {
    test: ['automated test', 'automated tests'],
    dast: ['runtime probe', 'runtime probes'],
    'template-control': ['template control', 'template controls'],
    scanner: ['scanner check', 'scanner checks'],
    config: ['configuration check', 'configuration checks'],
    'ai-review': ['AI review assessment', 'AI review assessments'],
    design: ['generated document', 'generated documents'],
    manual: ['human attestation', 'human attestations'],
  };
  for (const e of items) counts.set(e.type, (counts.get(e.type) ?? 0) + 1);
  const parts = [...counts.entries()].map(([type, n]) => {
    const [one, many] = label[type as Evidence['type']];
    return `${n} ${n === 1 ? one : many}`;
  });
  if (parts.length === 0) return 'nothing';
  if (parts.length === 1) return parts[0]!;
  return `${parts.slice(0, -1).join(', ')} and ${parts[parts.length - 1]}`;
}

export function decideStatus(ctx: StatusContext): StatusDecision {
  const strongPass = ctx.evidence.filter((e) => e.tier === 'strong' && e.passed);
  const strongFail = ctx.evidence.filter((e) => e.tier === 'strong' && !e.passed);
  const mediumPass = ctx.evidence.filter((e) => e.tier === 'medium' && e.passed);
  const mediumFail = ctx.evidence.filter((e) => e.tier === 'medium' && !e.passed);
  const contradicting = ctx.openFindings.filter(contradicts);
  const lowConfidenceOpen = ctx.openFindings.filter((f) => !contradicts(f));
  const aiPass = ctx.evidence.filter((e) => e.type === 'ai-review' && e.passed);
  const docPass = ctx.evidence.filter((e) => e.type === 'design' && e.passed);
  const manualPass = ctx.evidence.filter((e) => e.type === 'manual' && e.passed);
  const manualFail = ctx.evidence.filter((e) => e.type === 'manual' && !e.passed);

  const lowNote = lowConfidenceOpen.length > 0 ? ` ${plural(lowConfidenceOpen.length, 'low-confidence finding is', 'low-confidence findings are')} open but not counted (see the security report).` : '';

  if (ctx.manualOnly) {
    if (ctx.attestation?.result === 'yes' || manualPass.length > 0) {
      const who = ctx.attestation?.attestedBy ?? manualPass[0]?.producedBy ?? 'a person';
      return { status: 'attested', rationale: `This can only be confirmed by a person. ${who} confirmed it${ctx.attestation ? ` on ${ctx.attestation.attestedAt.slice(0, 10)}` : ''}; it is recorded, not independently verified.` };
    }
    if (ctx.attestation?.result === 'no' || manualFail.length > 0) {
      return { status: 'fail', rationale: `This can only be confirmed by a person, and ${manualFailText(ctx, manualFail)}.` };
    }
    return {
      status: 'not-verified',
      notVerifiedReason: ctx.notVerifiedReason === 'no-check-available' ? 'requires-human' : ctx.notVerifiedReason,
      rationale: `No automated check can decide this; a person must confirm it.${ctx.attestation?.result === 'not-sure' ? ` ${ctx.attestation.attestedBy} answered "not sure".` : ''}`,
    };
  }

  if (strongFail.length > 0 || mediumFail.length > 0 || contradicting.length > 0 || manualFail.length > 0 || ctx.attestation?.result === 'no') {
    const reasons: string[] = [];
    if (strongFail.length > 0) reasons.push(`${describeEvidence(strongFail)} failed`);
    if (mediumFail.length > 0) reasons.push(`${describeEvidence(mediumFail)} failed`);
    if (contradicting.length > 0) reasons.push(`${plural(contradicting.length, 'open finding')} (${contradicting.map((f) => f.id).join(', ')}) contradict${contradicting.length === 1 ? 's' : ''} this requirement`);
    if (manualFail.length > 0 || ctx.attestation?.result === 'no') reasons.push(manualFailText(ctx, manualFail));
    const failText = reasons.join('; ');
    if (strongPass.length > 0) {
      return { status: 'partial', rationale: `Mixed results: ${describeEvidence(strongPass)} passed, but ${failText}.${lowNote}` };
    }
    return { status: 'fail', rationale: `${failText.charAt(0).toUpperCase()}${failText.slice(1)}.${lowNote}` };
  }

  if (strongPass.length >= 1 || mediumPass.length >= 2) {
    const deterministic = [...strongPass, ...mediumPass];
    const onlyPartialCoverage = deterministic.every((e) => ctx.partialCoverage.has(e.id));
    if (onlyPartialCoverage) {
      return { status: 'partial', rationale: `${describeEvidence(deterministic)} passed, but the template controls involved only cover part of this requirement.${lowNote}` };
    }
    const aiNote = ctx.aiVerdict === 'fail' || ctx.aiVerdict === 'partial' ? ' The AI review disagreed (weak evidence); its note is kept for a developer.' : '';
    return { status: 'pass', rationale: `Verified by ${describeEvidence(deterministic)}.${aiNote}${lowNote}` };
  }

  if (mediumPass.length === 1) {
    return { status: 'partial', rationale: `A single static check passed (${describeEvidence(mediumPass)}); one more independent check, a test or a runtime probe would be needed to verify it.${lowNote}` };
  }

  if (ctx.aiVerdict === 'partial' || ctx.aiVerdict === 'fail') {
    return { status: 'partial', rationale: `The AI review judged this ${ctx.aiVerdict === 'fail' ? 'not met' : 'only partly met'} (citation verified); no automated check confirmed or contradicted it, so a developer should look.${lowNote}` };
  }

  if (ctx.attestation?.result === 'yes' || manualPass.length > 0) {
    const who = ctx.attestation?.attestedBy ?? manualPass[0]?.producedBy ?? 'a person';
    return { status: 'attested', rationale: `${who} confirmed this manually${ctx.attestation ? ` on ${ctx.attestation.attestedAt.slice(0, 10)}` : ''}. It is recorded, not independently verified.${lowNote}` };
  }

  if (aiPass.length > 0) {
    return { status: 'ai-assessed', rationale: `Only the AI code review supports this (citation verified). It is not counted as verified; a developer can confirm it with the steps below.${lowNote}` };
  }

  if (docPass.length > 0) {
    return { status: 'documented', rationale: `A generated document describes this (${docPass.map((e) => e.ref).join(', ')}), but nothing verified that it holds in practice.${lowNote}` };
  }

  return { status: 'not-verified', notVerifiedReason: ctx.notVerifiedReason, rationale: `${notVerifiedText(ctx.notVerifiedReason)}${lowNote}` };
}

export function notVerifiedText(reason: NotVerifiedReason): string {
  switch (reason) {
    case 'no-check-available':
      return 'No automated check covers this requirement in this version of SecureVibe.';
    case 'check-skipped-offline':
      return 'The check that covers this needs an internet connection and was skipped because the computer was offline.';
    case 'check-skipped-dependencies-missing':
      return 'The check that covers this could not run because the app’s packages did not install.';
    case 'check-errored':
      return 'The check that covers this ran into an error; see the run log.';
    case 'demo-mode':
      return 'This needs the AI review, which did not run because no AI key was configured (preview mode).';
    case 'requires-human':
      return 'Only a person can confirm this.';
    case 'requires-deployment':
      return 'This can only be checked once the app is deployed (hosting, TLS, operations).';
    case 'model-declined':
      return 'The AI model declined to assess this requirement.';
    case 'citation-unverified':
      return 'The AI review cited code that could not be found at the cited place, so its assessment was discarded.';
    case 'low-confidence':
      return 'The AI review was not confident enough for its assessment to count.';
  }
}
