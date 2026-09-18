/**
 * Run persistence helpers (CONTRACTS §9.5, §9.6): the run.json write-after-every-stage discipline, the
 * plain-text per-stage log files, and the startup sweep that marks runs still `running` after a crash/restart
 * as `interrupted` (they never silently look like they are still in progress).
 */
import { appendFileSync, existsSync, mkdirSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import type { PipelineRun, RunSummary, StageStatus } from '@shared/pipeline.js';
import type { ProjectStore } from '../store/index.js';
import { workerIsAlive } from './job.js';
import { isProjectId, isRunId, writeJsonAtomic } from '../store/index.js';

/** Appends a line to `pipeline/<runId>/stages/<stage>.log`, creating the folder on first use. */
export function appendStageLog(store: ProjectStore, projectId: string, runId: string, stage: string, text: string): string {
  const dir = store.projectPath(projectId, 'pipeline', runId, 'stages');
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${stage}.log`);
  const stamp = new Date().toISOString();
  appendFileSync(file, `[${stamp}] ${text}\n`);
  return file;
}

/** Persists the run after a stage transition (CONTRACTS §9.5: "Persists PipelineRun after every stage"). */
export async function persistRun(store: ProjectStore, run: PipelineRun): Promise<void> {
  await store.writeRun(run);
}

export function summaryOf(run: PipelineRun): RunSummary {
  const findingCounts: Record<string, number> = {};
  for (const f of run.findings) {
    if (f.status !== 'open' && f.status !== 'fix-attempted') continue;
    findingCounts[f.severity] = (findingCounts[f.severity] ?? 0) + 1;
  }
  return {
    id: run.id,
    mode: run.mode,
    startedAt: run.startedAt,
    ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}),
    status: run.status,
    ...(run.partial ? { partial: true } : {}),
    findingCounts,
    ...(run.compliance ? { complianceRating: run.compliance.overall.rating } : {}),
  };
}

/**
 * At startup, every run whose run.json still says `status: "running"` was interrupted by the previous process
 * exiting (crash, forced quit, machine restart) — mark it `interrupted` so the UI never shows a spinner that will
 * never finish. Returns the run ids that were changed.
 */
/**
 * Brings each app's status in line with its runs at startup: an app whose build finished is "built", one whose
 * build was interrupted is not left saying "building". Older workspaces predate the pipeline setting this.
 */
export function reconcileProjectStatusAtStartup(store: ProjectStore): string[] {
  const changed: string[] = [];
  for (const item of store.list()) {
    const project = store.get(item.id);
    if (!project) continue;
    const succeeded = project.runs.some((r) => r.status === 'succeeded');
    const next = succeeded ? 'built' : project.status === 'building' ? 'designed' : project.status;
    // "Rebuild needed" only means something when the answers changed after the build that is on disk.
    const lastRun = project.lastRunId ? store.readRun(project.id, project.lastRunId) : undefined;
    const builtFromCurrentAnswers =
      lastRun?.status === 'succeeded' && lastRun.provenance?.designProfileHash !== undefined && lastRun.provenance.designProfileHash === project.profileHash;
    const stale = builtFromCurrentAnswers ? false : project.buildStale;
    if (next === project.status && stale === project.buildStale) continue;
    store.update(project.id, (p) => {
      p.status = next;
      p.buildStale = stale;
      if (builtFromCurrentAnswers) p.designStale = false;
    });
    changed.push(project.id);
  }
  return changed;
}

export function markInterruptedRunsAtStartup(store: ProjectStore, now: Date = new Date()): string[] {
  const changed: string[] = [];
  if (!existsSync(store.projectsDir)) return changed;
  for (const projectId of readdirSync(store.projectsDir)) {
    if (!isProjectId(projectId)) continue;
    for (const runId of store.listRunIds(projectId)) {
      if (!isRunId(runId)) continue;
      const run = store.readRun(projectId, runId);
      if (!run || run.status !== 'running') continue;
      // A build in its own worker process survives a restart of SecureVibe: leave it be.
      if (workerIsAlive(store, projectId, runId)) continue;
      run.status = 'interrupted';
      run.finishedAt = now.toISOString();
      run.incomplete = true;
      run.failure = {
        message: 'SecureVibe was closed or restarted while this build was running. Start a new build to try again.',
        options: ['retry'],
      };
      store.writeRunSync(run);
      store.recordRunSummary(projectId, summaryOf(run));
      changed.push(runId);
    }
  }
  return changed;
}

export const TERMINAL_STAGE_STATUSES: readonly StageStatus[] = ['passed', 'failed', 'skipped', 'warning'];

export function isTerminalStageStatus(status: StageStatus): boolean {
  return TERMINAL_STAGE_STATUSES.includes(status);
}

export { writeJsonAtomic };
