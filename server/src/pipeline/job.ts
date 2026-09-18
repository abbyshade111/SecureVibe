/**
 * Durable builds: a build runs in its own worker process, not inside the web server.
 *
 *  - `job.json` in the run folder holds everything the worker needs to start the pipeline.
 *  - `worker.json` holds the worker's pid, so the server (even a freshly restarted one) can tell whether the build
 *    is still running, cancel it, and leave its child processes alone when sweeping stale ones.
 *  - `events.jsonl` is the progress stream: the worker appends one JSON line per event, the server tails it for
 *    the browser. A restart of SecureVibe loses nothing; the page simply reconnects.
 *
 * The worker is started detached in its own session, so closing the terminal, restarting SecureVibe, or the
 * desktop app stopping the server no longer ends a build.
 */
import { spawn } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { BuildPlan } from '@shared/project.js';
import type { RunMode, StageId } from '@shared/pipeline.js';
import type { GrantedApproval } from '../api/approvals.js';
import type { ProjectStore } from '../store/index.js';
import { isRunActive } from './runner.js';

export const JOB_FILE = 'job.json';
export const WORKER_FILE = 'worker.json';
export const EVENTS_FILE = 'events.jsonl';
export const WORKER_LOG = 'worker.log';

/** The part of RunPipelineOptions that can be written to disk and handed to a worker. */
export interface BuildJob {
  projectId: string;
  runId: string;
  mode: RunMode;
  spendingCapUsd: number;
  approval?: GrantedApproval & { spendingCapUsd: number };
  fixFindingIds?: string[];
  plan?: BuildPlan;
  /** Uploaded apps: nothing that runs their code, and no template-only checks. */
  uploaded?: boolean;
  /** Run without any AI call (a free re-check) even when a key is configured. */
  withoutAi?: boolean;
  /** The Security page: run only these checks and leave the compliance report alone. */
  checks?: StageId[];
  /** A build that continues an earlier, unfinished one: its code is kept and only the unwritten part is paid for. */
  resumeFromRunId?: string;
  createdAt: string;
}

export interface WorkerRecord {
  pid: number;
  startedAt: string;
}

export function writeJob(store: ProjectStore, job: BuildJob): string {
  const dir = store.runDir(job.projectId, job.runId);
  mkdirSync(dir, { recursive: true });
  const file = join(dir, JOB_FILE);
  writeFileSync(file, `${JSON.stringify(job, null, 2)}\n`, { mode: 0o600 });
  return file;
}

export function readJob(store: ProjectStore, projectId: string, runId: string): BuildJob | undefined {
  const file = join(store.runDir(projectId, runId), JOB_FILE);
  if (!existsSync(file)) return undefined;
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as BuildJob;
  } catch {
    return undefined;
  }
}

export function readWorker(store: ProjectStore, projectId: string, runId: string): WorkerRecord | undefined {
  const file = join(store.runDir(projectId, runId), WORKER_FILE);
  if (!existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as WorkerRecord;
    return Number.isInteger(parsed.pid) && parsed.pid > 1 ? parsed : undefined;
  } catch {
    return undefined;
  }
}

export function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM means the process exists but belongs to someone else; anything else means it is gone.
    return (err as NodeJS.ErrnoException).code === 'EPERM';
  }
}

/** True while the run's worker process is alive (whichever process asks). */
export function workerIsAlive(store: ProjectStore, projectId: string, runId: string): boolean {
  const worker = readWorker(store, projectId, runId);
  return worker !== undefined && isPidAlive(worker.pid);
}

/** True when the run is executing anywhere: in this process, or in a worker that is still alive. */
export function runIsLive(store: ProjectStore, runId: string | undefined): boolean {
  if (!runId) return false;
  if (isRunActive(runId)) return true;
  const run = store.findRun(runId);
  return run !== undefined && run.status === 'running' && workerIsAlive(store, run.projectId, runId);
}

/** Asks a worker to stop; the worker aborts its run and records it as cancelled. */
export function signalWorker(store: ProjectStore, projectId: string, runId: string, signal: NodeJS.Signals = 'SIGTERM'): boolean {
  const worker = readWorker(store, projectId, runId);
  if (!worker || !isPidAlive(worker.pid)) return false;
  try {
    process.kill(worker.pid, signal);
    return true;
  } catch {
    return false;
  }
}

/** The worker entry point, next to this module (`tsx` runs TypeScript directly, as `npm start` does). */
export function workerEntry(): string {
  return fileURLToPath(new URL('../cli/build-worker.ts', import.meta.url));
}

export interface SpawnWorkerOptions {
  store: ProjectStore;
  job: BuildJob;
  /** Environment for the worker (the server's own, so keys and settings match). */
  env?: NodeJS.ProcessEnv;
}

/**
 * Starts the worker for a job, detached from this process, with its output in `worker.log`. Returns the pid.
 * `tsx` is resolved from the server package the same way `npm start` runs it.
 */
export function spawnBuildWorker(opts: SpawnWorkerOptions): number {
  const dir = opts.store.runDir(opts.job.projectId, opts.job.runId);
  mkdirSync(dir, { recursive: true });
  const logFd = openSync(join(dir, WORKER_LOG), 'a', 0o600);
  // tsx is a workspace dependency: usually hoisted to the repository's node_modules, sometimes the server's own.
  const tsx = ['../../../node_modules/.bin/tsx', '../../node_modules/.bin/tsx']
    .map((rel) => fileURLToPath(new URL(rel, import.meta.url)))
    .find((candidate) => existsSync(candidate));
  if (!tsx) throw new Error('The build worker could not be started: tsx is not installed (run npm install).');
  const child = spawn(tsx, [workerEntry(), opts.job.projectId, opts.job.runId], {
    cwd: fileURLToPath(new URL('../..', import.meta.url)),
    env: { ...(opts.env ?? process.env), SECUREVIBE_WORKER: '1' },
    detached: true,
    stdio: ['ignore', logFd, logFd],
    windowsHide: true,
  });
  closeSync(logFd);
  child.unref();
  const pid = child.pid;
  if (!pid) throw new Error('The build worker could not be started.');
  writeFileSync(join(dir, WORKER_FILE), JSON.stringify({ pid, startedAt: new Date().toISOString() } satisfies WorkerRecord), { mode: 0o600 });
  return pid;
}
