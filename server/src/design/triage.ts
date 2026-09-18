/**
 * SbD step 6: risk triage. Escalation is computed exactly as the framework states
 * (any critical "No", score >= 6, or any escalation trigger). The user-facing text never mentions the score
 * or the word "escalate": it shows "Extra care" paired with what was done about it.
 */
import type { EscalationTrigger, RiskTriage, SbdChecklistEntry, ThreatModel } from '@shared/design.js';
import { profileHasPersonalData, profileHasSensitiveData, type DesignProfile } from '@shared/profile.js';
import { checklistTotals } from './checklist.js';
import { DATA_CATEGORY_LABELS, listWords, type ProfileFacts } from './conditions.js';

export const SBD_THRESHOLD = 6;

export function escalationTriggers(profile: DesignProfile, f: ProfileFacts): EscalationTrigger[] {
  const sensitive = profileHasPersonalData(profile) || profileHasSensitiveData(profile);
  const exposure = f.publicAudience || profile.deployment.target !== 'local-only';
  const dataWords = listWords(
    [...new Set([...f.personalCategories, ...f.sensitiveCategories])].map((c) => DATA_CATEGORY_LABELS[c]),
  );
  return [
    {
      id: 'sensitive-data',
      name: 'Sensitive or regulated data',
      triggered: sensitive,
      reason: sensitive
        ? `The app handles ${dataWords || 'information about people'}.`
        : 'The app stores no information about people.',
    },
    {
      id: 'external-exposure',
      name: 'New external exposure',
      triggered: exposure,
      reason: exposure
        ? f.publicAudience
          ? 'People outside your team will use it.'
          : profile.deployment.target === 'local-network'
            ? 'It will be reachable on your local network.'
            : 'It is intended to go on the internet.'
        : 'Only you or your team use it, on this computer.',
    },
    {
      id: 'novel-technology',
      name: 'Novel technology or pattern',
      triggered: f.ai,
      reason: f.ai ? 'It includes an AI assistant that accepts untrusted input.' : 'No AI assistant or unusual technology is used.',
    },
    {
      id: 'tier-1-impact',
      name: 'High business impact (Tier 1)',
      triggered: f.highImpact,
      reason: f.highImpact
        ? 'You said an outage or breach would seriously hurt your business.'
        : 'An outage would be an inconvenience, not a disaster.',
    },
  ];
}

export function triageRisk(
  profile: DesignProfile,
  f: ProfileFacts,
  checklist: SbdChecklistEntry[],
  threatModel: ThreatModel,
  escalationAcknowledgedAt?: string,
): RiskTriage {
  const totals = checklistTotals(checklist);
  const triggers = escalationTriggers(profile, f);
  const triggered = triggers.filter((t) => t.triggered);
  const escalate = totals.criticalNo.length > 0 || totals.score >= SBD_THRESHOLD || triggered.length > 0;

  const escalationReasons: string[] = [];
  for (const id of totals.criticalNo) {
    const entry = checklist.find((e) => e.id === id);
    escalationReasons.push(`Critical control ${id} is not met: ${entry?.justification ?? ''}`.trim());
  }
  if (totals.score >= SBD_THRESHOLD) escalationReasons.push(`Checklist score ${totals.score} reaches the threshold of ${SBD_THRESHOLD}.`);
  for (const t of triggered) escalationReasons.push(`Trigger "${t.name}": ${t.reason}`);

  const ackText = escalationAcknowledgedAt
    ? ` on ${escalationAcknowledgedAt.slice(0, 10)}`
    : ' (pending: the owner has not acknowledged it yet)';
  const escalationHandling = escalate
    ? `Escalation required — satisfied by: generated STRIDE threat model + owner acknowledgment${ackText} (no independent AppSec review was performed)`
    : 'No escalation required. The design was reviewed by rules and the AI second opinion; no independent AppSec review was performed.';

  const level: RiskTriage['level'] = escalate ? 'high' : totals.score > 0 ? 'normal' : 'low';
  const openThreats = threatModel.threats.filter((t) => t.status !== 'mitigated').length;

  return {
    score: totals.score,
    threshold: SBD_THRESHOLD,
    notApplicableCount: totals.notApplicableCount,
    criticalNo: totals.criticalNo,
    triggers,
    level,
    escalate,
    escalationReasons,
    escalationHandling,
    threatModelRequired: escalate,
    extraCareLabel: escalate ? 'Extra care' : 'Standard care',
    plainLanguage: plainLanguage(f, triggered, totals.criticalNo, threatModel.threats.length, openThreats, escalationAcknowledgedAt),
  };
}

function plainLanguage(
  f: ProfileFacts,
  triggered: EscalationTrigger[],
  criticalNo: string[],
  threatCount: number,
  openThreats: number,
  ackAt?: string,
): string {
  const parts: string[] = [];
  const whyBits = triggered.map((t) => lowerFirst(t.reason.replace(/\.$/, '')));
  if (triggered.length || criticalNo.length) {
    const why = whyBits.length ? `Because ${listWords(whyBits)}, ` : 'Because some protections cannot be fully provided by a local app, ';
    parts.push(`${why}${f.appName} gets extra care.`);
    parts.push(
      `What we did: we wrote a threat model that lists ${threatCount} ways things could go wrong and the protection for each. ${openThreats === 0 ? 'Every one of them is covered by the built-in protections.' : `${openThreats} of them ${openThreats === 1 ? 'needs' : 'need'} an action from you before the app is used for real. ${openThreats === 1 ? 'It is' : 'They are'} listed in the threat model.`}`,
    );
    if (criticalNo.length) {
      parts.push(
        `Some protections that big companies use (${listWords(criticalNo)}) do not exist for an app on one computer. Each has a plan with a date and an owner.`,
      );
    }
    parts.push(
      ackAt
        ? `You acknowledged this review on ${ackAt.slice(0, 10)}. No outside security expert reviewed it.`
        : 'Please read the threat model and confirm you understand it. No outside security expert reviewed it.',
    );
  } else {
    parts.push(`${f.appName} needs standard care.`);
    parts.push(
      `What we did: we filled in the design checklist and wrote a threat model with ${threatCount} items, all covered by the built-in protections. No outside security expert reviewed it.`,
    );
  }
  return parts.join(' ');
}

function lowerFirst(text: string): string {
  return text.charAt(0).toLowerCase() + text.slice(1);
}
