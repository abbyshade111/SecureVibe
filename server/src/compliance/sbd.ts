/**
 * SbD checklist evaluation (CONTRACTS §7, DESIGN §13.2): re-checks each of the 36 design-time checklist entries
 * against the build's own evidence, computes the deployment-time view from `data/knowledge/sbd-rules.json`, and
 * fills in the 10 SbD process steps with who/what actually performed each one for this run.
 */
import type { SbdEvaluatedEntry, SbdEvaluation } from '@shared/compliance.js';
import type { DesignArtifacts, SbdChecklistEntry } from '@shared/design.js';
import type { SbdRule } from '@shared/knowledge.js';
import type { Attestation, HumanCodeReview } from '@shared/project.js';
import type { SbdView } from '../frameworks/index.js';
import type { ManifestControlResult, RunMeta } from './types.js';

export interface EvaluateSbdInput {
  design: DesignArtifacts;
  sbdRules: SbdRule[];
  sbd: SbdView;
  manifestResults: ManifestControlResult[];
  attestations: Attestation[];
  humanReview?: HumanCodeReview;
  runMeta: RunMeta;
}

interface PointerResolution {
  /** False when the pointer's kind is not something this evaluation can check (treated as informational only). */
  known: boolean;
  passed: boolean;
}

function resolvePointer(pointer: string, entry: SbdChecklistEntry, manifestResults: ManifestControlResult[], attestations: Attestation[]): PointerResolution {
  const [kind, ...rest] = pointer.split(':');
  const rest1 = rest.join(':');
  switch (kind) {
    case 'template': {
      const result = manifestResults.find((r) => r.controlId === rest1);
      if (!result || !result.expected) return { known: false, passed: true };
      return { known: true, passed: result.passed };
    }
    case 'design':
      // Design-time facts (a selected pattern, the architecture itself) cannot fail after the build.
      return { known: false, passed: true };
    case 'doc': {
      const control = manifestResults.find((r) =>
        r.checks.some((c) => c.check.type === 'doc-generated' && c.check.file === rest1),
      );
      if (!control) return { known: false, passed: true };
      const check = control.checks.find((c) => c.check.type === 'doc-generated' && c.check.file === rest1);
      if (!check) return { known: false, passed: true };
      return { known: true, passed: check.passed };
    }
    case 'attestation':
    case 'manual': {
      const found = attestations.some((a) => a.standard === 'sbd' && a.requirementId === entry.id && a.result === 'yes');
      const denied = attestations.some((a) => a.standard === 'sbd' && a.requirementId === entry.id && a.result === 'no');
      if (!found && !denied) return { known: false, passed: true };
      return { known: true, passed: found };
    }
    default:
      return { known: false, passed: true };
  }
}

function verifyEntry(
  entry: SbdChecklistEntry,
  manifestResults: ManifestControlResult[],
  attestations: Attestation[],
): { verification: SbdEvaluatedEntry['verification']; note?: string } {
  if (entry.status === 'n-a') return { verification: 'verified', note: 'Not applicable by design; nothing to contradict it.' };
  const resolutions = entry.evidence.map((p) => resolvePointer(p, entry, manifestResults, attestations));
  const known = resolutions.filter((r) => r.known);
  if (known.length === 0) {
    return { verification: 'design-only', note: 'This was decided at design time; the build produced no independent check of it.' };
  }
  const failed = known.filter((r) => !r.passed).length;
  if (failed > 0) {
    return { verification: 'contradicted', note: `${failed} of ${known.length} referenced control(s) did not hold on the generated code.` };
  }
  return { verification: 'verified', note: `Confirmed by ${known.length} check(s) on the generated code.` };
}

function deploymentTimeFor(entries: SbdChecklistEntry[], sbdRules: SbdRule[]): SbdEvaluation['deploymentTime'] {
  const byId = new Map(sbdRules.map((r) => [r.id, r]));
  return entries.map((e) => {
    const rule = byId.get(e.id);
    const outcome = rule?.outcomes.find((o) => o.justification === e.justification);
    const status = outcome?.deploymentTimeStatus ?? e.status;
    const note =
      outcome?.deploymentNote ?? e.deploymentNote ?? 'No change is expected for this control once the app is reachable over a network.';
    return { id: e.id, status, note };
  });
}

function processSteps(design: DesignArtifacts, sbd: SbdView, runMeta: RunMeta): SbdEvaluation['processSteps'] {
  const names = sbd.processSteps;
  const peer = design.peerReview;
  const threatDone = design.threatModel !== undefined;
  const approved = Boolean(runMeta.approvedBy && runMeta.approvedAt);
  const steps: { performedBy: string; completed: boolean; artifact?: string; note?: string }[] = [
    { performedBy: 'rules', completed: design.securityRequirements.length > 0, artifact: 'design/design.md#1-security-requirements' },
    { performedBy: 'rules', completed: design.architecture.components.length > 0, artifact: 'design/diagram.mmd' },
    { performedBy: 'rules', completed: design.patterns.length > 0, artifact: 'design/design.md#3-patterns-applied' },
    { performedBy: 'rules', completed: design.checklist.length === 36, artifact: 'design/design.md#4-sbd-review-checklist' },
    {
      performedBy: peer ? (peer.performedBy === 'skipped' ? 'not performed' : peer.performedBy) : 'not performed',
      completed: peer !== undefined && peer.performedBy !== 'skipped',
      artifact: 'design/design.md#5-second-opinion',
      ...(peer?.skippedReason ? { note: peer.skippedReason } : {}),
    },
    { performedBy: 'rules', completed: true, artifact: 'design/design.md#6-risk-triage' },
    {
      performedBy: design.riskTriage.threatModelRequired ? (threatDone ? (design.threatModel!.performedBy === 'claude' ? 'claude' : 'rules') : 'not performed') : 'not required',
      completed: !design.riskTriage.threatModelRequired || threatDone,
      artifact: 'design/threat-model.md',
    },
    { performedBy: 'rules', completed: true, artifact: 'design/design.md' },
    {
      performedBy: runMeta.approvedBy ?? 'not performed',
      completed: approved,
      artifact: 'run.json#approvedBy',
      ...(!approved ? { note: 'No human has approved a build for this design yet.' } : {}),
    },
    { performedBy: 'rules', completed: true, note: 'Editing an answer after this point marks the design as changed and shows a rebuild banner.' },
  ];
  return steps.map((s, i) => ({ step: i + 1, name: names[i] ?? `Step ${i + 1}`, ...s }));
}

export function evaluateSbd(input: EvaluateSbdInput): SbdEvaluation {
  const { design, sbdRules, sbd, manifestResults, attestations, runMeta } = input;
  const entries: SbdEvaluatedEntry[] = design.checklist.map((entry) => {
    // An owner's "not applicable" with a reason (the latest answer for this control): the control stays in the
    // list, reads as not applicable because of that reason, names who decided and when, and stops counting as
    // an unmet critical control. It is an answer, not a dismissal: the reason is required and printed.
    const decided = attestations
      .filter((a) => a.standard === 'sbd' && a.requirementId === entry.id)
      .sort((a, b) => b.attestedAt.localeCompare(a.attestedAt))[0];
    if (decided?.result === 'not-applicable') {
      const reason = `Not applicable, because ${decided.note.trim() || 'the owner said so'} (decided by ${decided.attestedBy} on ${decided.attestedAt.slice(0, 10)}).`;
      return { ...entry, status: 'n-a', score: 0, actions: [], note: reason, verification: 'verified', verificationNote: reason, evidenceIds: [] };
    }
    const { verification, note } = verifyEntry(entry, manifestResults, attestations);
    return { ...entry, verification, ...(note ? { verificationNote: note } : {}), evidenceIds: [] };
  });

  const yes = entries.filter((e) => e.status === 'yes').length;
  const no = entries.filter((e) => e.status === 'no').length;
  const na = entries.filter((e) => e.status === 'n-a').length;
  const critical = entries.filter((e) => e.critical);
  const criticalCounts = {
    yes: critical.filter((e) => e.status === 'yes').length,
    no: critical.filter((e) => e.status === 'no').length,
    'n-a': critical.filter((e) => e.status === 'n-a').length,
  };

  const criticalNo = critical.filter((e) => e.status === 'no').map((e) => e.id);
  const verifiedCount = entries.filter((e) => e.verification === 'verified').length;
  const contradicted = entries.filter((e) => e.verification === 'contradicted');
  const summary =
    contradicted.length === 0
      ? `${design.riskTriage.plainLanguage} After the build, ${verifiedCount} of ${entries.length} checklist items were confirmed by what was actually built.`
      : `${design.riskTriage.plainLanguage} After the build, ${contradicted.length} checklist item(s) (${contradicted.map((e) => e.id).join(', ')}) no longer match what was found — see the details for each.`;

  return {
    framework: sbd.framework,
    version: sbd.version,
    entries,
    score: design.riskTriage.score,
    threshold: design.riskTriage.threshold,
    // From the entries as evaluated, so a critical control the owner recorded as not applicable, with a reason,
    // no longer holds the rating at "at risk"; the design's own list is what it was at design time.
    criticalNo,
    // Recomputed with that list, so the escalation formula (CONTRACTS §7) still holds after an owner's decision.
    escalate: criticalNo.length > 0 || design.riskTriage.score >= design.riskTriage.threshold || design.riskTriage.triggers.some((t) => t.triggered),
    escalationReasons: design.riskTriage.escalationReasons,
    escalationHandling: design.riskTriage.escalationHandling,
    counts: { yes, no, 'n-a': na },
    criticalCounts,
    notApplicableIds: entries.filter((e) => e.status === 'n-a').map((e) => e.id),
    deploymentTime: deploymentTimeFor(design.checklist, sbdRules),
    processSteps: processSteps(design, sbd, runMeta),
    summary,
  };
}
