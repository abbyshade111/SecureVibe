/** Database hygiene, transactions, idempotency, scheduler and retention (TPL-DB-02, TPL-IDEMPOTENCY-01, TPL-SCHED-01, TPL-DATA-01). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { CookieJar, startApp, type RunningApp } from '../helpers/app.ts';
import { exampleNote, fields, headers as headerNames, paths, users } from '../helpers/conventions.ts';
import { templateRoot } from '../helpers/features.ts';

describe('db', () => {
  let app: RunningApp;
  let member: CookieJar;
  let hasNotes = false;

  before(async () => {
    app = await startApp();
    member = await app.login(users.member);
    hasNotes = await app.featureEnabled('example');
  });
  after(async () => {
    await app?.stop();
  });

  /** One page of the notes list. */
  async function listNotesPage(jar: CookieJar, query = ''): Promise<unknown[]> {
    const res = await app.fetch(`${paths.notesApi}${query}`, { jar, headers: { Accept: 'application/json' } });
    const body = (await res.json()) as unknown;
    if (Array.isArray(body)) return body;
    const obj = body as Record<string, unknown>;
    for (const key of ['items', 'data', 'notes', 'results']) if (Array.isArray(obj[key])) return obj[key] as unknown[];
    throw new Error(`cannot find the list in ${JSON.stringify(body).slice(0, 200)}`);
  }

  /** Every note of the signed-in user: list responses are bounded (LIMIT), so the pages are walked. */
  async function listNotes(jar: CookieJar): Promise<unknown[]> {
    const all: unknown[] = [];
    for (let page = 1; page <= 50; page++) {
      const items = await listNotesPage(jar, `?page=${page}`);
      all.push(...items);
      if (items.length === 0) break;
    }
    return all;
  }

  test('V16.4.2 the database and data directory are private to the app user and use safe pragmas', async () => {
    const dbPath = app.dbPath();
    assert.equal(statSync(dbPath).mode & 0o777, 0o600, 'the database file must be mode 0600');
    assert.equal(statSync(app.dataDir).mode & 0o777, 0o700, 'DATA_DIR must be mode 0700');
    for (const suffix of ['-wal', '-shm']) {
      const side = `${dbPath}${suffix}`;
      if (existsSync(side)) assert.equal(statSync(side).mode & 0o777, 0o600, `${suffix} file must be mode 0600`);
    }
    const journal = app.dbAll<{ journal_mode: string }>('PRAGMA journal_mode')[0]?.journal_mode;
    assert.equal(String(journal).toLowerCase(), 'wal', 'the database must run in WAL mode');
    const tables = app.dbTables();
    for (const t of ['_migrations', 'users', 'sessions', 'audit_log']) assert.ok(tables.includes(t), `table ${t} must exist (found ${tables.join(', ')})`);
    const migrations = app.dbAll<{ n: number }>('SELECT count(*) AS n FROM _migrations')[0]?.n ?? 0;
    assert.ok(Number(migrations) >= 1, 'applied migrations must be recorded');
    const logPath = app.logPath();
    if (existsSync(logPath)) assert.equal(statSync(logPath).mode & 0o777 & 0o077, 0, 'the log file must not be readable by other users');
  });

  test('V2.3.3 per-user quotas are enforced inside a transaction: no partial writes past the limit', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const jar = await app.login(users.member2);
    const start = (await listNotes(jar)).length;
    let created = 0;
    let rejected: Response | undefined;
    for (let i = 0; i < 250; i++) {
      const res = await app.json('POST', paths.notesApi, { ...exampleNote, title: `quota ${i}` }, jar);
      await res.text();
      if (res.status === 200 || res.status === 201) created++;
      else {
        rejected = res;
        break;
      }
    }
    if (!rejected) return t.skip('the per-user quota was not reached within 250 records');
    assert.ok([400, 403, 409, 413, 422, 429].includes(rejected.status), `quota rejection must be a client error, got ${rejected.status}`);
    const after = (await listNotes(jar)).length;
    assert.equal(after, start + created, 'the rejected record must not be partially written');
    const again = await app.json('POST', paths.notesApi, { ...exampleNote, title: 'one more' }, jar);
    await again.text();
    assert.equal(again.status, rejected.status, 'the quota must keep rejecting');
    assert.equal((await listNotes(jar)).length, after);
  });

  test('RR-05 JSON API mutations honor Idempotency-Key: a retried create returns the stored response and writes once', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const route = await app.findRoute('POST', /^\/api\/notes$/);
    if (!route?.idempotent) return t.skip('the notes create route does not declare idempotent: true');
    const key = randomUUID();
    const before = (await listNotes(member)).length;
    const first = await app.json('POST', paths.notesApi, { ...exampleNote, title: 'idempotent create' }, member, { headers: { [headerNames.idempotency]: key } });
    const firstBody = await first.text();
    assert.ok([200, 201].includes(first.status), `create failed: ${first.status} ${firstBody}`);
    const second = await app.json('POST', paths.notesApi, { ...exampleNote, title: 'idempotent create' }, member, { headers: { [headerNames.idempotency]: key } });
    const secondBody = await second.text();
    assert.equal(second.status, first.status, 'the replay must return the stored status');
    assert.equal(secondBody, firstBody, 'the replay must return the stored body');
    assert.equal((await listNotes(member)).length, before + 1, 'the retried request must not create a second record');
    const otherUser = await app.login(users.member2);
    const stolen = await app.json('POST', paths.notesApi, { ...exampleNote, title: 'idempotent create' }, otherUser, { headers: { [headerNames.idempotency]: key } });
    const stolenBody = await stolen.text();
    assert.ok(stolen.status >= 400 || stolenBody !== firstBody, "another user must not receive the first user's stored response");
  });

  test('RR-05 concurrent updates use optimistic concurrency: a stale update is rejected', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const update = await app.findRoute('PATCH', /^\/api\/notes\/:/) ?? (await app.findRoute('PUT', /^\/api\/notes\/:/));
    if (!update) return t.skip('no update route for notes');
    const create = await app.json('POST', paths.notesApi, { ...exampleNote, title: 'concurrency' }, member);
    const created = (await create.json()) as Record<string, unknown>;
    const id = String(created.id ?? (created.data as Record<string, unknown> | undefined)?.id ?? (created.note as Record<string, unknown> | undefined)?.id);
    const versionField = ['updatedAt', 'updated_at', 'version'].find((f) => f in created);
    if (!versionField) return t.skip('the note DTO exposes no version field for optimistic concurrency');
    const version = created[versionField];
    const one = await app.json(update.method, paths.noteApi(id), { title: 'first writer', [versionField]: version }, member);
    const oneBody = await one.text();
    assert.ok(one.status < 400, `first update failed: ${one.status} ${oneBody}`);
    const two = await app.json(update.method, paths.noteApi(id), { title: 'second writer (stale)', [versionField]: version }, member);
    await two.text();
    assert.ok([409, 412, 400, 422].includes(two.status), `a stale update must be rejected, got ${two.status}`);
  });

  test('V2.4.1 list endpoints are bounded (LIMIT) and never return unbounded result sets', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const res = await app.fetch(`${paths.notesApi}?limit=100000`, { jar: member, headers: { Accept: 'application/json' } });
    const text = await res.text();
    assert.ok([200, 400].includes(res.status), `huge limit answered ${res.status}: ${text.slice(0, 200)}`);
    if (res.status === 200) {
      const list = await listNotesPage(member, '?limit=100000');
      assert.ok(list.length <= 1000, 'a list must be capped');
    }
  });

  test('V15.2.2 scheduler jobs are registry-declared, locked against overlap and never take user input', async (t) => {
    if (!(await app.featureEnabled('scheduler'))) return t.skip('feature "scheduler" is not enabled');
    const tables = app.dbTables();
    // The template calls it scheduler_jobs; a generated app may simply call it jobs.
    const jobsTable = tables.find((t) => /^(scheduler_)?jobs$/.test(t));
    assert.ok(jobsTable, `a jobs table must exist (found ${tables.join(', ')})`);
    const columns = app.dbColumns(jobsTable);
    assert.ok(columns.includes('lock_until'), 'jobs must carry lock_until for overlap protection');
    const jobs = app.dbAll<{ name?: string; id?: string }>(`SELECT * FROM ${jobsTable}`);
    assert.ok(jobs.length >= 1, 'at least one job must be registered');
    const registry = await app.routes();
    const jobRoutes = registry.routes.filter((r) => /job|schedule|cron/i.test(r.path) && r.method !== 'GET');
    for (const r of jobRoutes) assert.ok(r.auth === 'role:admin', `${r.method} ${r.path} must be admin-only`);
  });

  test('DM-05 retention job: a retention period is configured, documented and the deletion path pseudonymises records', async (t) => {
    if (!(await app.featureEnabled('retention'))) return t.skip('feature "retention" is not enabled');
    assert.ok(existsSync(join(templateRoot, 'docs', 'data-retention.md')), 'docs/data-retention.md must exist');
    const retentionApp = await startApp({ env: { RETENTION_MONTHS: '6' } });
    try {
      if (retentionApp.dbTables().includes('jobs')) {
        const jobs = retentionApp.dbAll<Record<string, unknown>>('SELECT * FROM jobs');
        assert.ok(jobs.some((j) => /retention|purge|cleanup/i.test(JSON.stringify(j))), 'a retention job must be registered');
      }
      const jar = await retentionApp.login(users.member2);
      const re = await retentionApp.reauth(jar);
      await re.text();
      const since = new Date().toISOString();
      const del = await retentionApp.submitForm(paths.dataDelete, { [fields.password]: retentionApp.password }, jar);
      const delBody = await del.text();
      assert.ok(del.status < 400, `account deletion failed: ${del.status} ${delBody.slice(0, 200)}`);
      const events = await retentionApp.waitForEvent('data.deleted', since);
      assert.ok(events.length >= 1, 'data.deleted must be logged');
      assert.equal(await retentionApp.canLogin(users.member2, retentionApp.password), false, 'a deleted account must not log in');
      assert.equal(retentionApp.dbContains(users.member2), false, 'the email address must be removed or pseudonymised everywhere');
    } finally {
      await retentionApp.stop();
    }
  });
});
