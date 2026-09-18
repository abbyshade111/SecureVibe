-- Background jobs (src/lib/scheduler.ts, src/features/scheduler). One row per registry-declared job name; jobs
-- take a lease (lock_until) before running so two overlapping ticks never run the same job at once.
CREATE TABLE IF NOT EXISTS scheduler_jobs (
  name TEXT PRIMARY KEY,
  last_run_at TEXT,
  lock_until TEXT,
  last_error TEXT,
  last_duration_ms INTEGER,
  run_count INTEGER NOT NULL DEFAULT 0
);
