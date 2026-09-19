/**
 * What an app's findings are *now*, and which check said so.
 *
 * Two things make this less obvious than reading the latest run.
 *
 * First, decisions. A run record holds what the checks found when they ran; what is still open depends on what a
 * person has decided since — accepted as it stands, or judged never to have been a real problem — and those live on
 * the project, matched by fingerprint so they survive a rebuild.
 *
 * Second, checks are re-run one at a time. Someone fixes the thing a check complained about and runs that check
 * again; that run holds only that check's findings and says nothing about the others. Reading the latest run alone
 * would wipe out everything the other checks found; reading only the last run that ran everything would ignore the
 * fix and keep reporting a finding that is gone. Neither is true. So each check contributes the findings of the most
 * recent run that actually ran it, which is the same rule the Security page already uses for check *statuses* —
 * "the result of the last run that did include it".
 */
import type { Finding } from '@shared/findings.js';
import type { PipelineRun, StageId } from '@shared/pipeline.js';
import { CHECK_FOR_SOURCE, RERUNNABLE_CHECKS } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';
import type { ProjectStore } from '../store/index.js';

/** The finding sources a check accounts for, read back off the one shared mapping (CHECK_FOR_SOURCE). */
function sourcesOf(check: StageId): string[] {
  return Object.entries(CHECK_FOR_SOURCE)
    .filter(([, mapped]) => mapped === check)
    .map(([source]) => source);
}

/** The findings of one run as they stand now: the owner's decisions are what makes a finding open or not. */
export function withDecisions(run: PipelineRun, project: Project): Finding[] {
  return run.findings.map((f) => {
    const decision = project.findingDecisions.find((d) => d.fingerprint === f.fingerprint);
    return decision ? { ...f, status: decision.status, triage: decision.triage } : f;
  });
}

export interface CurrentFindings {
  /** Every check's latest word, with the owner's decisions applied. */
  findings: Finding[];
  /** Which run each check's findings came from, so a caller can say when each number was formed. */
  runByCheck: Map<StageId, { runId: string; finishedAt?: string }>;
  /** The last run that ran every check: what the app was like when everything was looked at together. */
  lastFullRun?: PipelineRun;
  /** How many checks have been run again since that one, and so contribute newer numbers than it. */
  checksRerunSince: number;
  /** True when a run record could not be read; the caller should not report the result as complete. */
  unreadable: boolean;
}

/**
 * Every check's latest result for one app. Walks the runs newest first with no ceiling: the run that last ran a
 * given check may be many re-runs ago, and stopping early would report a check that has run as one that never has.
 */
export function currentFindings(store: ProjectStore, project: Project): CurrentFindings {
  const runIds = store.listRunIds(project.id).reverse();
  const runByCheck = new Map<StageId, { runId: string; finishedAt?: string }>();
  const findings: Finding[] = [];
  const seenFingerprints = new Set<string>();
  let lastFullRun: PipelineRun | undefined;
  let unreadable = false;
  // Findings from the AI review are not re-runnable on their own (that check costs money), so they are taken from
  // the last run that ran everything, along with anything from a source no current check claims.
  const claimed = new Set(RERUNNABLE_CHECKS.flatMap((check) => sourcesOf(check)));

  for (const runId of runIds) {
    const run = store.readRun(project.id, runId);
    if (!run) {
      unreadable = true;
      continue;
    }
    if (run.status === 'running') continue;
    const decided = withDecisions(run, project);

    for (const check of RERUNNABLE_CHECKS) {
      if (runByCheck.has(check)) continue;
      const stage = run.stages.find((s) => s.id === check);
      // A check that did not run in this run says nothing about the app; an older run that did is the truth.
      if (!stage || stage.status === 'skipped' || stage.status === 'running') continue;
      runByCheck.set(check, { runId: run.id, ...(stage.finishedAt ? { finishedAt: stage.finishedAt } : {}) });
      const sources = sourcesOf(check);
      for (const finding of decided) {
        if (!sources.includes(finding.source)) continue;
        if (seenFingerprints.has(finding.fingerprint)) continue;
        seenFingerprints.add(finding.fingerprint);
        findings.push(finding);
      }
    }

    if (!lastFullRun && !run.partial) {
      lastFullRun = run;
      for (const finding of decided) {
        if (claimed.has(finding.source)) continue;
        if (seenFingerprints.has(finding.fingerprint)) continue;
        seenFingerprints.add(finding.fingerprint);
        findings.push(finding);
      }
    }

    if (lastFullRun && runByCheck.size === RERUNNABLE_CHECKS.length) break;
  }

  const checksRerunSince = lastFullRun ? [...runByCheck.values()].filter((source) => source.runId !== lastFullRun!.id).length : 0;
  return { findings, runByCheck, ...(lastFullRun ? { lastFullRun } : {}), checksRerunSince, unreadable };
}

/** The newest run that holds a finding with this id, for recording a decision about it. */
export function findRunWithFinding(store: ProjectStore, project: Project, findingId: string): PipelineRun | undefined {
  for (const runId of store.listRunIds(project.id).reverse()) {
    const run = store.readRun(project.id, runId);
    if (run?.findings.some((f) => f.id === findingId)) return run;
  }
  return undefined;
}
