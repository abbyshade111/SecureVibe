/**
 * Prioritised, de-duplicated recommendations (CONTRACTS §9.4, DESIGN §13.12): gathered from failing/partial/
 * owner-facing not-verified requirements, unresolved SbD checklist actions and open findings.
 */
import type { Recommendation, RequirementResult, SbdEvaluatedEntry } from '@shared/compliance.js';
import { isOpen, type Finding } from '@shared/findings.js';

const PRIORITY_RANK: Record<Recommendation['priority'], number> = { high: 0, medium: 1, low: 2 };

function ownerFromAction(owner: string): Recommendation['who'] {
  if (owner.startsWith('owner:') || owner === 'owner') return 'owner';
  if (owner === 'hosting-provider') return 'hosting-provider';
  if (owner === 'security-professional') return 'security-professional';
  return 'developer';
}

function ownerFromWhoCanFix(who: Finding['whoCanFix']): Recommendation['who'] {
  switch (who) {
    case 'owner':
      return 'owner';
    case 'hosting-provider':
      return 'hosting-provider';
    case 'securevibe':
      return 'developer';
    default:
      return 'developer';
  }
}

function fromRequirements(results: RequirementResult[]): Recommendation[] {
  const out: Recommendation[] = [];
  for (const r of results) {
    const isOwnerNotVerified = r.status === 'not-verified' && r.manualVerification?.whoCanDo === 'owner';
    if (r.status !== 'fail' && r.status !== 'partial' && !isOwnerNotVerified) continue;
    out.push({
      id: `REC-req-${r.id}`,
      priority: r.status === 'fail' ? 'high' : r.status === 'partial' ? 'medium' : 'low',
      title: `${r.id}: ${r.description}`,
      detail: r.remediation ?? r.rationale,
      who: r.manualVerification?.whoCanDo ?? 'developer',
      ...(r.manualVerification?.estimatedEffort ? { effort: r.manualVerification.estimatedEffort } : {}),
      relatedRequirements: [r.id],
      relatedFindings: r.findingIds,
      relatedControls: [],
    });
  }
  return out;
}

function fromSbd(entries: SbdEvaluatedEntry[]): Recommendation[] {
  const out: Recommendation[] = [];
  for (const e of entries) {
    if (e.status !== 'no') continue;
    for (const [i, action] of e.actions.entries()) {
      out.push({
        id: `REC-sbd-${e.id}-${i}`,
        priority: e.critical ? 'high' : e.severityIfNo === 'high' ? 'high' : e.severityIfNo === 'medium' ? 'medium' : 'low',
        title: `${e.id}: ${action.text}`,
        detail: e.justification,
        who: ownerFromAction(action.owner),
        ...(action.dueBy ? { dueBy: action.dueBy } : {}),
        relatedRequirements: [],
        relatedFindings: [],
        relatedControls: [e.id],
      });
    }
  }
  return out;
}

function fromFindings(findings: Finding[]): Recommendation[] {
  const out: Recommendation[] = [];
  for (const f of findings) {
    if (!isOpen(f) || f.whoCanFix === 'securevibe') continue;
    out.push({
      id: `REC-finding-${f.id}`,
      priority: f.priority === 'P1' || f.priority === 'P2' ? 'high' : f.priority === 'P3' ? 'medium' : 'low',
      title: f.title,
      detail: f.remediation.summary,
      who: ownerFromWhoCanFix(f.whoCanFix),
      relatedRequirements: [],
      relatedFindings: [f.id],
      relatedControls: [],
    });
  }
  return out;
}

/** Same person, same headline: keep the first (requirements-derived recommendations are the most specific). */
function dedupe(recs: Recommendation[]): Recommendation[] {
  const seen = new Map<string, Recommendation>();
  for (const r of recs) {
    const key = `${r.who}|${r.title}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, r);
      continue;
    }
    existing.relatedRequirements = [...new Set([...existing.relatedRequirements, ...r.relatedRequirements])];
    existing.relatedFindings = [...new Set([...existing.relatedFindings, ...r.relatedFindings])];
    existing.relatedControls = [...new Set([...existing.relatedControls, ...r.relatedControls])];
    if (PRIORITY_RANK[r.priority] < PRIORITY_RANK[existing.priority]) existing.priority = r.priority;
  }
  return [...seen.values()];
}

/**
 * 1 when the action waits on something that has not happened — hosting the app online, using it across teams.
 * Those are real and are kept; they are simply not what an owner does next, and the list is read top-down.
 */
function waitsForSomething(r: Recommendation): number {
  return r.dueBy && r.dueBy.trim() !== '' && !/^(now|immediately|today)$/i.test(r.dueBy.trim()) ? 1 : 0;
}

export function buildRecommendations(results: RequirementResult[], sbdEntries: SbdEvaluatedEntry[], findings: Finding[]): Recommendation[] {
  const combined = dedupe([...fromRequirements(results), ...fromSbd(sbdEntries), ...fromFindings(findings)]);
  // An urgent finding and a merely important one both count as "high", and only the first five actions are shown,
  // so alphabetical order could push the thing blocking the app off the end of the list. Anything tied to an
  // urgent finding sorts to the front of its band.
  const urgent = new Set(findings.filter((f) => f.priority === 'P1').map((f) => f.id));
  const blocksUse = (r: Recommendation): number => (r.relatedFindings.some((id) => urgent.has(id)) ? 0 : 1);
  return combined
    .sort(
      (a, b) =>
        // Anything blocking use, then everything due now, then what is waiting on something that has not
        // happened yet. Severity alone put "if your organisation has a central sign-in system" and "when the app
        // is hosted online" at the top of the list for an owner with neither an organisation nor a host, which
        // buries the things she could actually do today under two she cannot.
        blocksUse(a) - blocksUse(b) ||
        waitsForSomething(a) - waitsForSomething(b) ||
        PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority] ||
        a.title.localeCompare(b.title),
    )
    .map((r, i) => ({ ...r, id: `REC-${String(i + 1).padStart(3, '0')}` }));
}
