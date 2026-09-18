/**
 * Scheduled background jobs (contract "Scheduler", TPL-SCHED-01). Registers the two jobs this template ships —
 * data retention (only when `RETENTION_MONTHS` is set) and a periodic audit-chain check — starts the in-process
 * runner, and exposes a read-only admin page listing every job's last run. Mounted only when `scheduler` is
 * switched on in `securevibe.features.json`.
 */
import type { Router } from 'express';
import { config } from '../../config.ts';
import { verifyChain } from '../../security/audit.ts';
import { logger } from '../../lib/logger.ts';
import { registerJob, startScheduler, jobStatuses } from '../../lib/scheduler.ts';
import { renderPage } from '../../lib/views.ts';
import { all, run } from '../../db/index.ts';
import { listEntities } from '../../security/authz.ts';
import { defineRoute } from '../../security/routes.ts';

const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

/** Tables this job never touches: accounts and keys have their own lifecycle (disable/revoke). */
const RETENTION_EXCLUDED_TABLES = new Set(['users', 'api_keys', 'uploads']);

/**
 * Deletes records untouched for longer than `RETENTION_MONTHS` (contract §1.9 "retention", docs/data-retention.md):
 * uploaded files when that feature is installed, and every registered record type that tracks `updated_at`.
 */
async function retentionJob(): Promise<void> {
  if (config.retentionMonths === undefined) return;
  const cutoff = new Date(Date.now() - config.retentionMonths * 30 * DAY_MS).toISOString();

  // The uploads feature is optional and may have been removed from this app, so it is loaded only if present.
  const uploadsModule = new URL('../uploads/repo.ts', import.meta.url).href;
  try {
    const uploads = (await import(uploadsModule)) as { deleteUploadsCreatedBefore(cutoffIso: string): number };
    const deleted = uploads.deleteUploadsCreatedBefore(cutoff);
    if (deleted > 0) logger.info({ deleted, cutoff }, 'retention job removed old uploads');
  } catch (err) {
    if ((err as { code?: string }).code !== 'ERR_MODULE_NOT_FOUND') throw err;
  }

  for (const entity of listEntities()) {
    if (RETENTION_EXCLUDED_TABLES.has(entity.table)) continue;
    const columns = all<{ name: string }>(`PRAGMA table_info(${entity.table})`).map((c) => c.name);
    if (!columns.includes('updated_at')) continue;
    const deleted = run(`DELETE FROM ${entity.table} WHERE updated_at < ?`, [cutoff]).changes;
    if (deleted > 0) logger.info({ entity: entity.name, deleted, cutoff }, 'retention job removed old records');
  }
  // Sessions and the audit log have their own retention: see src/security/session.ts#cleanupSessions and
  // src/security/audit.ts#pruneAudit, both run from src/server.ts.
}

/** Re-checks the hash chain periodically so tampering is caught even between visits to /admin/audit/verify. */
function auditVerifyJob(): void {
  const result = verifyChain();
  if (!result.ok) {
    throw new Error(`audit log chain check failed at seq ${result.brokenAtSeq ?? '?'}: ${result.reason ?? 'unknown reason'}`);
  }
}

export function register(router: Router): void {
  registerJob({ name: 'retention', description: 'Deletes records and uploads untouched for longer than RETENTION_MONTHS.', intervalMs: DAY_MS, run: retentionJob });
  registerJob({ name: 'audit-verify', description: 'Recomputes the audit log hash chain.', intervalMs: HOUR_MS, run: auditVerifyJob });
  startScheduler();

  defineRoute(router, { method: 'GET', path: '/admin/scheduler', auth: 'role:admin', summary: 'Scheduled jobs' }, (req, res) => {
    renderPage(req, res, 'admin/scheduler', { title: 'Scheduled jobs', jobs: jobStatuses(), retentionMonths: config.retentionMonths ?? null });
  });
}
