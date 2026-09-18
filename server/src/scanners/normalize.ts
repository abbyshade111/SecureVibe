/**
 * finalizeFindings: the one place every scanner's raw Findings pass through before they reach the
 * pipeline, the compliance engine and the reports (CONTRACTS §9.2). It:
 *  1. de-duplicates findings that share a fingerprint, merging `sourcesReporting`, CWE ids and mappings;
 *  2. drops a `lint` finding that sits on the same file/line as a `sast` finding (SAST wins — CONTRACTS §3)
 *     and folds it into the SAST finding's `sourcesReporting` instead of losing it silently;
 *  3. fills in anything missing from `data/knowledge/remediation.json` (a scanner other than sast/lint/
 *     secrets/config may not have looked the rule id up itself);
 *  4. adjusts severity for the deployment context, recording why;
 *  5. computes `priority` from the (possibly adjusted) severity, confidence and exploitability;
 *  6. resolves `whoCanFix` for cases the owning scanner could not know on its own;
 *  7. applies persisted decisions (accepted / false-positive) by fingerprint;
 *  8. sets `firstSeenRun`/`lastSeenRun` from the previous run's findings;
 *  9. assigns the final, stable "F-0001" ids and sorts the result the way the reports expect it.
 */
import type { DeploymentTarget } from '@shared/profile.js';
import type { FindingDecision } from '@shared/project.js';
import { computePriority, isOpen, sortFindings, type Finding, type Severity, type Triage } from '@shared/findings.js';
import { matchesAnyGlob } from '../generator/files.js';
import { unique } from './sast/findings.js';
import type { ScanContext } from './types.js';

/**
 * A reviewed decision that covers every finding of one rule (optionally only under some paths). Used by the
 * self-assessment, whose code does not follow the generated-app conventions some rules encode; each entry carries
 * its justification, which the reports show next to the finding.
 */
export interface RuleDecision {
  ruleId: string;
  /** Glob patterns (relative to the scanned folder); omitted means everywhere. */
  paths?: string[];
  status: 'accepted' | 'false-positive';
  triage: Triage;
}

export interface FinalizeOptions {
  deploymentTarget: DeploymentTarget;
  decisions: FindingDecision[];
  ruleDecisions?: RuleDecision[];
  /** The previous run's finalized findings, for firstSeenRun/lastSeenRun continuity. */
  previousFindings?: Finding[];
  runId: string;
}

const SEVERITY_STEPS: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

function downgradeOneStep(severity: Severity): Severity {
  const i = SEVERITY_STEPS.indexOf(severity);
  return SEVERITY_STEPS[Math.min(i + 1, SEVERITY_STEPS.length - 1)]!;
}

function locationKey(f: Finding): string | undefined {
  if (!f.location?.file || f.location.line === undefined) return undefined;
  return `${f.location.file}:${f.location.line}`;
}

/** Merges `b` into `a` in place: unions sourcesReporting/cwe/mappings, keeps the more severe copy's headline text. */
function mergeInto(a: Finding, b: Finding): void {
  a.sourcesReporting = unique([...a.sourcesReporting, ...b.sourcesReporting, b.source]);
  a.cwe = unique([...a.cwe, ...b.cwe]);
  a.mappings = {
    asvs: unique([...a.mappings.asvs, ...b.mappings.asvs]),
    aisvs: unique([...a.mappings.aisvs, ...b.mappings.aisvs]),
    sbd: unique([...a.mappings.sbd, ...b.mappings.sbd]),
  };
  const aRank = SEVERITY_STEPS.indexOf(a.severity);
  const bRank = SEVERITY_STEPS.indexOf(b.severity);
  if (bRank < aRank) {
    a.title = b.title;
    a.severity = b.severity;
    a.severityBase = b.severityBase ?? b.severity;
    a.description = b.description;
    a.impact = b.impact;
    a.evidence = b.evidence;
  }
}

/** Step 1: exact-fingerprint de-duplication. */
function dedupeByFingerprint(findings: Finding[]): Finding[] {
  const byFingerprint = new Map<string, Finding>();
  const order: string[] = [];
  for (const f of findings) {
    const existing = byFingerprint.get(f.fingerprint);
    if (!existing) {
      const copy: Finding = { ...f, sourcesReporting: unique([...f.sourcesReporting, f.source]) };
      byFingerprint.set(f.fingerprint, copy);
      order.push(f.fingerprint);
    } else {
      mergeInto(existing, f);
    }
  }
  return order.map((fp) => byFingerprint.get(fp)!);
}

/** Step 2: a `lint` finding at the same file:line as a `sast` finding is redundant — SAST wins. */
function preferSastOverLint(findings: Finding[]): Finding[] {
  const sastByLocation = new Map<string, Finding>();
  for (const f of findings) {
    if (f.source !== 'sast') continue;
    const key = locationKey(f);
    if (key) sastByLocation.set(key, f);
  }
  return findings.filter((f) => {
    if (f.source !== 'lint') return true;
    const key = locationKey(f);
    const sastFinding = key ? sastByLocation.get(key) : undefined;
    if (!sastFinding) return true;
    mergeInto(sastFinding, f);
    return false;
  });
}

/** Step 3: fill in anything a scanner did not already look up for itself. */
function enrichFromKnowledge(f: Finding, ctx: Pick<ScanContext, 'knowledge'>): void {
  const known = ctx.knowledge?.remediation?.[f.ruleId];
  if (!known) return;
  if (!f.remediation.summary) f.remediation = { summary: known.remediation.summary, steps: known.remediation.steps, example: known.remediation.example, references: known.remediation.references };
  if (!f.description) f.description = known.description;
  if (!f.impact) f.impact = known.impact;
  f.cwe = unique([...f.cwe, ...known.cwe]);
  f.mappings = {
    asvs: unique([...f.mappings.asvs, ...known.asvs]),
    aisvs: unique([...f.mappings.aisvs, ...known.aisvs]),
    sbd: unique([...f.mappings.sbd, ...known.sbd]),
  };
  if (!f.verification && known.howToConfirmFixed) f.verification = { howToConfirmFixed: known.howToConfirmFixed, rerunCommand: 'npm run verify -- <app folder>' };
}

/** Step 4: local-only apps cannot be reached by anyone off the machine, so a network-exposure finding is a step less urgent. */
function adjustSeverityForDeployment(f: Finding, deploymentTarget: DeploymentTarget): void {
  f.severityBase = f.severityBase ?? f.severity;
  if (deploymentTarget !== 'local-only' || f.exploitability !== 'requires-network-exposure') return;
  const adjusted = downgradeOneStep(f.severityBase);
  if (adjusted === f.severity) return;
  f.severity = adjusted;
  f.adjustmentReason = 'Lowered one level: this app only runs on your own computer (local-only), so reaching this would require someone already on your machine or network.';
}

/** Step 6: resolves who is expected to act, for the cases a scanner has no way to know by itself. */
const HOSTING_PROVIDER_RULES = new Set(['config.tls-mode-consistent', 'config.bind-loopback-default', 'deps.vulnerability']);
const OWNER_RULES = new Set(['config.no-default-admin', 'secrets.env-file-committed', 'config.readme-run-instructions', 'config.security-md-present']);

function resolveWhoCanFix(f: Finding): Finding['whoCanFix'] {
  if (HOSTING_PROVIDER_RULES.has(f.ruleId)) return 'hosting-provider';
  if (OWNER_RULES.has(f.ruleId)) return 'owner';
  return f.whoCanFix;
}

function applyDecision(f: Finding, decisions: FindingDecision[], ruleDecisions: RuleDecision[] = []): void {
  const decision =
    decisions.find((d) => d.fingerprint === f.fingerprint) ??
    ruleDecisions.find((d) => d.ruleId === f.ruleId && (!d.paths || (f.location?.file !== undefined && matchesAnyGlob(f.location.file, d.paths))));
  if (!decision) return;
  f.status = decision.status;
  f.triage = decision.triage;
}

function applyContinuity(f: Finding, previous: Finding[] | undefined, runId: string): void {
  const prior = previous?.find((p) => p.fingerprint === f.fingerprint);
  f.firstSeenRun = prior?.firstSeenRun ?? runId;
  f.lastSeenRun = runId;
  // A finding the previous run marked fixed/accepted/false-positive that reappears is open again.
  if (prior && !isOpen(prior) && f.status === 'open') {
    // keep status open; nothing else to do, but make the reappearance visible in evidence text.
    if (!f.evidence.includes('reappeared')) f.evidence = `${f.evidence} (reappeared after being marked "${prior.status}" in run ${prior.lastSeenRun ?? '(previous)'})`;
  }
}

export function finalizeFindings(findings: Finding[], ctx: ScanContext, opts: FinalizeOptions): Finding[] {
  let result = dedupeByFingerprint(findings);
  result = preferSastOverLint(result);

  for (const f of result) {
    enrichFromKnowledge(f, ctx);
    adjustSeverityForDeployment(f, opts.deploymentTarget);
    f.exploitability = f.exploitability ?? 'requires-network-exposure';
    f.priority = computePriority(f);
    f.whoCanFix = resolveWhoCanFix(f);
    applyDecision(f, opts.decisions, opts.ruleDecisions);
    applyContinuity(f, opts.previousFindings, opts.runId);
  }

  result = sortFindings(result);
  result.forEach((f, i) => {
    f.id = `F-${String(i + 1).padStart(4, '0')}`;
  });
  return result;
}
