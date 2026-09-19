/**
 * Test-bootstrap mode (NODE_ENV=test + SECUREVIBE_TEST_MODE=1 only). Seeds one user per role and one record per
 * entity so the SecureVibe runtime scanner can probe every route as anonymous / wrong role / non-owner, and exposes
 * four helper endpoints under /__securevibe. None of this exists in production.
 */
import type { Router } from 'express';
import { z } from 'zod';
import { config } from '../config.ts';
import { get, run, withTransaction } from '../db/index.ts';
import { installConfirmedSeed } from '../features/auth/mfa.ts';
import { createUser, findUserByEmail, isAdminRole, type UserRow } from '../features/auth/repo.ts';
import { listEntities } from '../security/authz.ts';
import { queryAudit } from '../security/audit.ts';
import { hashPasswordSync } from './test-hash.ts';
import { resetRateLimits } from '../security/rate-limit.ts';
import { defineRoute, routeSchemasAsJson, summariseRoutes } from '../security/routes.ts';
import { base32Decode } from '../security/totp.ts';
import { logger } from './logger.ts';

export interface SeededUser {
  email: string;
  role: string;
  mfa: boolean;
}

export function seededUserPlan(): SeededUser[] {
  const nonAdmin = config.roles.filter((r) => !r.isAdmin).map((r) => r.name);
  const first = nonAdmin[0] ?? 'member';
  const last = nonAdmin[nonAdmin.length - 1] ?? 'member';
  return [
    { email: 'admin@test.local', role: config.adminRole, mfa: Boolean(config.SECUREVIBE_TEST_TOTP_SEED) },
    { email: 'staff@test.local', role: first, mfa: false },
    { email: 'member@test.local', role: last, mfa: false },
    { email: 'member2@test.local', role: last, mfa: false },
  ];
}

function ensureUser(email: string, role: string, passwordHash: string): UserRow {
  const existing = findUserByEmail(email);
  if (existing) {
    if (existing.role !== role) run('UPDATE users SET role = ? WHERE id = ?', [role, existing.id]);
    run('UPDATE users SET password_hash = ?, status = ?, must_change_password = 0, failed_logins = 0, lock_until = NULL WHERE id = ?', [passwordHash, 'active', existing.id]);
    return existing;
  }
  return createUser({ email, passwordHash, role, name: email.split('@')[0] ?? email });
}

function ensureAdminMfa(userId: string, seedBase32: string): void {
  const secret = base32Decode(seedBase32);
  if (secret.length < 10) throw new Error('SECUREVIBE_TEST_TOTP_SEED must be a base32 string of at least 16 characters.');
  installConfirmedSeed(userId, secret);
}

/** Idempotent: safe to run on every start in test mode. */
export function seedTestData(): void {
  if (!config.testMode) return;
  const password = config.SECUREVIBE_TEST_PASSWORD;
  if (!password) throw new Error('SECUREVIBE_TEST_PASSWORD is required in test mode.');
  const passwordHash = hashPasswordSync(password);
  withTransaction(() => {
    for (const plan of seededUserPlan()) {
      const user = ensureUser(plan.email, plan.role, passwordHash);
      if (plan.mfa && config.SECUREVIBE_TEST_TOTP_SEED) ensureAdminMfa(user.id, config.SECUREVIBE_TEST_TOTP_SEED);
      else if (isAdminRole(plan.role) && !plan.mfa) {
        run("UPDATE users SET totp_secret_enc = NULL, totp_confirmed = 0, totp_used_steps = '[]' WHERE id = ?", [user.id]);
      }
    }
    const member = findUserByEmail('member@test.local');
    if (member) {
      for (const entity of listEntities()) {
        if (!entity.seed) continue;
        if (entity.sampleId && entity.sampleId(member.id)) continue;
        entity.seed(member.id);
      }
    }
  });
  logger.info({ users: seededUserPlan().map((u) => u.email) }, 'test mode: seeded users');
}

/** Which job to run, or nothing for every job. A name is only ever matched against the jobs declared in code. */
const RunJobsBody = z.strictObject({ job: z.string().trim().min(1).max(60).optional() });

interface SchedulerModule {
  listJobs(): { name: string }[];
  runJobNow(name: string): Promise<boolean>;
}

/** The scheduler module when this app has one; undefined when the feature was left out and the file with it. */
async function loadScheduler(): Promise<SchedulerModule | undefined> {
  try {
    return (await import(new URL('./scheduler.ts', import.meta.url).href)) as SchedulerModule;
  } catch (err) {
    if ((err as { code?: string }).code === 'ERR_MODULE_NOT_FOUND') return undefined;
    throw err;
  }
}

const EventsQuery = z.strictObject({ since: z.string().datetime({ offset: true }).optional() });

export function registerTestModeRoutes(router: Router): void {
  defineRoute(router, { method: 'GET', path: '/__securevibe/routes', auth: 'public', kind: 'api', summary: 'Test mode: route registry export' }, (_req, res) => {
    const member = findUserByEmail('member@test.local');
    // Each route's body schema lets the runtime scanner build a valid create request for any record type.
    const schemas = routeSchemasAsJson();
    res.json({
      routes: summariseRoutes().map((r, i) => ({ ...r, bodySchema: schemas[i]?.body ?? null })),
      roles: config.roles.map((r) => r.name),
      adminRole: config.adminRole,
      entities: listEntities().map((e) => ({
        name: e.name,
        ownerField: e.ownerField,
        sample: { id: member && e.sampleId ? (e.sampleId(member.id) ?? null) : null },
      })),
      seededUsers: seededUserPlan(),
    });
  });
  defineRoute(
    router,
    { method: 'GET', path: '/__securevibe/events', auth: 'public', kind: 'api', schema: { query: EventsQuery }, summary: 'Test mode: last 500 security events' },
    (req, res) => {
      // Event-specific fields are flattened next to the fixed columns so probes can filter on e.g. `factor` or `bucket`.
      const rows = queryAudit({ since: req.valid.query.since, limit: 500 }).reverse();
      res.json({ events: rows.map(({ fields, ...record }) => ({ ...fields, ...record })) });
    },
  );
  defineRoute(router, { method: 'POST', path: '/__securevibe/reset-rate-limits', auth: 'public', kind: 'api', csrf: false, summary: 'Test mode: clear rate limits' }, (_req, res) => {
    resetRateLimits();
    run('UPDATE users SET failed_logins = 0, lock_until = NULL');
    res.json({ ok: true });
  });

  /**
   * Runs scheduled jobs now, whatever their interval says, so a test can watch a job that is only due once a day
   * without waiting a day. Each job still runs under its own lease. `{"job":"<name>"}` runs one; no body runs all.
   *
   * Administrators only, unlike the other three endpoints here. Anything that can set work going belongs behind the
   * administrator role wherever it exists at all — which is also the rule `tests/security/db.test.ts` enforces on
   * every route whose path mentions a job or a schedule, and there is no reason for this one to be the exception.
   */
  defineRoute(
    router,
    { method: 'POST', path: '/__securevibe/run-jobs', auth: 'role:admin', kind: 'api', csrf: false, schema: { body: RunJobsBody }, summary: 'Test mode: run scheduled jobs now' },
    async (req, res) => {
      // The scheduler is an optional feature, so its module may not be part of this app at all: it is loaded here
      // rather than imported, the same way the retention job loads the uploads module.
      const scheduler = await loadScheduler();
      if (!scheduler) {
        res.json({ ran: [], jobs: [], note: 'this app has no scheduler' });
        return;
      }
      const wanted = (req.valid.body as { job?: string }).job;
      const names = wanted ? [wanted] : scheduler.listJobs().map((j) => j.name);
      const ran: string[] = [];
      for (const name of names) if (await scheduler.runJobNow(name)) ran.push(name);
      res.json({ ran, jobs: scheduler.listJobs().map((j) => j.name) });
    },
  );
  // Keep the DB warm for the first request in tests.
  get('SELECT 1 AS ok');
}
