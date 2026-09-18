/**
 * SbD step 4: the 36-control review checklist, filled from data/knowledge/sbd-rules.json (first matching
 * outcome wins) with the framework's statements and severities from data/frameworks/sbd-checklist-0.5.0.json.
 */
import { SbdDomainSchema, type SbdChecklistEntry, type SbdDomain } from '@shared/design.js';
import type { SbdRule } from '@shared/knowledge.js';
import type { DesignProfile } from '@shared/profile.js';
import type { Attestation } from '@shared/project.js';
import { matchesSbdWhen, type ProfileFacts } from './conditions.js';
import type { SbdChecklistView, SbdSeverity } from './types.js';

export const SBD_SCORE: Record<SbdSeverity, number> = { low: 1, medium: 2, high: 4 };

/** ADRs that record the decision behind each control (ids from adrs.ts). */
const ADR_BY_CONTROL: Record<string, string[]> = {
  'AS-01': ['ADR-006'],
  'AS-03': ['ADR-002'],
  'AS-05': ['ADR-008'],
  'DM-01': ['ADR-003', 'ADR-007'],
  'DM-02': ['ADR-003', 'ADR-006'],
  'DM-03': ['ADR-002'],
  'DM-05': ['ADR-007'],
  'RR-01': ['ADR-008'],
  'RR-02': ['ADR-005', 'ADR-008'],
  'RR-06': ['ADR-006'],
  'RR-07': ['ADR-006'],
  'AC-01': ['ADR-006'],
  'AC-02': ['ADR-001', 'ADR-002'],
  'AC-03': ['ADR-001'],
  'AC-05': ['ADR-003'],
  'AC-06': ['ADR-007'],
  'MT-01': ['ADR-007'],
  'MT-06': ['ADR-007'],
  'MT-07': ['ADR-007'],
};

export function fillChecklist(
  profile: DesignProfile,
  f: ProfileFacts,
  rules: SbdRule[],
  sbd: SbdChecklistView,
  attestations: Attestation[],
): SbdChecklistEntry[] {
  const entries: SbdChecklistEntry[] = [];
  const ruleById = new Map(rules.map((r) => [r.id, r]));

  for (const control of sbd.controls) {
    const domainId = parseDomain(control.domain);
    const rule = ruleById.get(control.id);
    const attestation = attestations.find(
      (a) => a.standard === 'sbd' && a.requirementId === control.id && a.result === 'yes',
    );
    const outcome = rule?.outcomes.find((o) => matchesSbdWhen(o.when, f, attestation !== undefined));
    const severityIfNo = raiseSeverity(rule?.severityIfNo ?? control.severityIfNo, f.highImpact);
    const status = outcome?.status ?? 'no';
    const justification =
      outcome?.justification ??
      `No decision rule is available for ${control.id}. It is treated as not implemented until a developer reviews it.`;

    const actions = (outcome?.actions ?? []).map((a) => ({
      text: a.text,
      owner: normaliseOwner(a.owner, profile),
      ...(a.dueBy ? { dueBy: a.dueBy } : {}),
    }));
    if (status === 'no' && actions.length === 0) {
      actions.push({
        text: `Review ${control.id} (${control.statement}) and decide how to address it.`,
        owner: 'developer',
        dueBy: defaultDueBy(f),
      });
    }
    const firstAction = actions[0];
    const mitigationPlan =
      control.critical && status === 'no' && firstAction
        ? {
            owner: `owner:${profile.deployment.owner.name}`,
            dueBy: firstAction.dueBy ?? defaultDueBy(f),
            action: firstAction.text,
          }
        : undefined;

    const evidence = [...(outcome?.evidence ?? [])];
    if (attestation) evidence.push(`manual:attestation:${attestation.id}`);

    const deploymentNote =
      outcome?.deploymentNote ??
      (outcome?.deploymentTimeStatus
        ? `If ${f.appName} is put on the internet, this control becomes "${outcome.deploymentTimeStatus}" and must be checked again.`
        : undefined);

    entries.push({
      id: control.id,
      domain: domainId,
      statement: control.statement,
      critical: control.critical,
      status,
      justification,
      severityIfNo,
      score: status === 'no' ? SBD_SCORE[severityIfNo] : 0,
      evidence,
      actions,
      ...(mitigationPlan ? { mitigationPlan } : {}),
      ...(deploymentNote ? { deploymentNote } : {}),
      ...(outcome?.deploymentTimeStatus ? { comment: `Status once deployed on the internet: ${outcome.deploymentTimeStatus}.` } : {}),
      adrIds: ADR_BY_CONTROL[control.id] ?? [],
      ...(outcome?.note ? { note: outcome.note } : {}),
    });
  }
  return entries;
}

export function checklistTotals(entries: SbdChecklistEntry[]): {
  score: number;
  criticalNo: string[];
  notApplicableCount: number;
} {
  return {
    score: entries.reduce((sum, e) => sum + e.score, 0),
    criticalNo: entries.filter((e) => e.critical && e.status === 'no').map((e) => e.id),
    notApplicableCount: entries.filter((e) => e.status === 'n-a').length,
  };
}

/** Business impact "high" raises the severity of a missing control one step (CONTRACTS §7). */
export function raiseSeverity(severity: SbdSeverity, highImpact: boolean): SbdSeverity {
  if (!highImpact) return severity;
  if (severity === 'low') return 'medium';
  return 'high';
}

export function defaultDueBy(f: ProfileFacts): string {
  if (f.internet) return 'before internet deployment';
  if (f.lan) return 'before sharing on the local network';
  return 'before the app is used for real work';
}

function normaliseOwner(owner: string, profile: DesignProfile): string {
  if (owner === 'owner') return `owner:${profile.deployment.owner.name}`;
  return owner;
}

function parseDomain(id: string): SbdDomain {
  const parsed = SbdDomainSchema.safeParse(id);
  if (!parsed.success) throw new Error(`Unknown SbD checklist domain "${id}" in the framework data`);
  return parsed.data;
}
