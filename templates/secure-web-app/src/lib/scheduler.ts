/**
 * In-process scheduler (contract "Scheduler", TPL-SCHED-01). Jobs are declared in code only — nothing here ever
 * reads a name, a schedule or a command from user input (V15.2.2, RR-01) — and each job takes a lease
 * (`lock_until` in the `scheduler_jobs` table) before it runs, so two overlapping ticks, or two processes sharing
 * a database, never run the same job at once (RR-03). Intended for the single local-first process this template
 * runs as; the lease still protects against an accidental double start.
 */
import { get, nowIso, run, withTransaction } from '../db/index.ts';
import { logger } from './logger.ts';

export interface ScheduledJob {
  /** Stable identifier; also the primary key in `scheduler_jobs`. */
  name: string;
  description: string;
  intervalMs: number;
  run: () => void | Promise<void>;
}

interface JobRow {
  name: string;
  last_run_at: string | null;
  lock_until: string | null;
  last_error: string | null;
  last_duration_ms: number | null;
  run_count: number;
}

const registry = new Map<string, ScheduledJob>();
const TICK_MS = 30_000;
const LEASE_MS = 5 * 60_000;

let timer: NodeJS.Timeout | undefined;
let started = false;

/** Registers a job. Call once at startup, before `startScheduler()`; registering the same name twice is a no-op. */
export function registerJob(job: ScheduledJob): void {
  if (registry.has(job.name)) return;
  if (job.intervalMs < 1000) throw new Error(`Job "${job.name}": intervalMs must be at least 1000.`);
  registry.set(job.name, job);
}

export function listJobs(): ScheduledJob[] {
  return [...registry.values()];
}

function jobRow(name: string): JobRow | undefined {
  return get<JobRow>('SELECT * FROM scheduler_jobs WHERE name = ?', [name]);
}

/** Job rows for every registered job (a job that has never run yet still gets a row with null timestamps). */
export function jobStatuses(): JobRow[] {
  return listJobs().map((j) => {
    run('INSERT OR IGNORE INTO scheduler_jobs (name, run_count) VALUES (?, 0)', [j.name]);
    return jobRow(j.name) ?? { name: j.name, last_run_at: null, lock_until: null, last_error: null, last_duration_ms: null, run_count: 0 };
  });
}

/**
 * Takes the lease for `job` if it is due and not already held. Returns true when this call may run it.
 * `ignoreInterval` skips the "is it due yet" half — never the lease — and is only ever set by `runJobNow`.
 */
function tryAcquire(job: ScheduledJob, nowMs: number, ignoreInterval = false): boolean {
  return withTransaction(() => {
    run('INSERT OR IGNORE INTO scheduler_jobs (name, run_count) VALUES (?, 0)', [job.name]);
    const row = jobRow(job.name)!;
    const nowIsoStr = new Date(nowMs).toISOString();
    if (row.lock_until && row.lock_until > nowIsoStr) return false;
    if (!ignoreInterval && row.last_run_at && new Date(row.last_run_at).getTime() + job.intervalMs > nowMs) return false;
    run('UPDATE scheduler_jobs SET lock_until = ? WHERE name = ?', [new Date(nowMs + LEASE_MS).toISOString(), job.name]);
    return true;
  });
}

async function runOne(job: ScheduledJob, ignoreInterval = false): Promise<void> {
  if (!tryAcquire(job, Date.now(), ignoreInterval)) return;
  const started_ = Date.now();
  try {
    await job.run();
    run('UPDATE scheduler_jobs SET last_run_at = ?, lock_until = NULL, last_error = NULL, last_duration_ms = ?, run_count = run_count + 1 WHERE name = ?', [
      nowIso(),
      Date.now() - started_,
      job.name,
    ]);
  } catch (err) {
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 500);
    logger.error({ job: job.name, err: message }, 'scheduled job failed');
    run('UPDATE scheduler_jobs SET last_run_at = ?, lock_until = NULL, last_error = ?, last_duration_ms = ?, run_count = run_count + 1 WHERE name = ?', [
      nowIso(),
      message,
      Date.now() - started_,
      job.name,
    ]);
  }
}

/** Runs every due job once, right now (used by the initial kick and available for tests). */
export async function runDueJobsOnce(): Promise<void> {
  for (const job of registry.values()) await runOne(job);
}

/**
 * Runs one job now whatever its interval says, still under its lease so an overlapping tick cannot run it at the
 * same time. Returns false when there is no such job, or when its lease is already held.
 *
 * This exists so a test can observe a job that is only due once an hour without waiting an hour: it is reached only
 * through the test-mode endpoint in src/lib/test-mode.ts, which does not exist outside test mode, and a runtime
 * probe checks that it answers 404 in production.
 */
export async function runJobNow(name: string): Promise<boolean> {
  const job = registry.get(name);
  if (!job) return false;
  const before = jobRow(name)?.run_count ?? 0;
  await runOne(job, true);
  return (jobRow(name)?.run_count ?? 0) > before;
}

/** Starts the interval runner. Safe to call more than once — later calls are a no-op. */
export function startScheduler(): void {
  if (started) return;
  started = true;
  // Every declared job gets its row immediately, so the admin page and an audit show what is scheduled even
  // before anything has run.
  for (const job of listJobs()) run('INSERT OR IGNORE INTO scheduler_jobs (name, run_count) VALUES (?, 0)', [job.name]);
  timer = setInterval(() => {
    runDueJobsOnce().catch((err) => logger.error({ err: err instanceof Error ? err.message : String(err) }, 'scheduler tick failed'));
  }, TICK_MS);
  timer.unref();
  // A short-lived process (or a test) should still see a due job run without waiting a full tick.
  const kick = setTimeout(() => {
    runDueJobsOnce().catch((err) => logger.error({ err: err instanceof Error ? err.message : String(err) }, 'scheduler kick failed'));
  }, 1_000);
  kick.unref();
}

export function stopScheduler(): void {
  if (timer) clearInterval(timer);
  timer = undefined;
  started = false;
}

/** Test/inspection only: clears the registry so a fresh set of jobs can be registered. */
export function resetRegistry(): void {
  registry.clear();
}
