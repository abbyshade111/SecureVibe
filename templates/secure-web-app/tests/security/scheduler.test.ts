/** Background jobs (contract "Scheduler", TPL-SCHED-01). Skips when the scheduler feature is off. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { startApp, type RunningApp } from '../helpers/app.ts';
import { users } from '../helpers/conventions.ts';
import { skipReason } from '../helpers/features.ts';

describe('scheduler', () => {
  let app: RunningApp;
  let enabled = false;

  before(async () => {
    app = await startApp();
    enabled = await app.featureEnabled('scheduler');
  });
  after(async () => {
    await app?.stop();
  });

  test('V15.2.2 scheduler jobs are declared in code, never accept user input, and run under a lease that is always released', async (t) => {
    if (!enabled) return t.skip(skipReason('scheduler'));

    // No route, form or API accepts a job name, a cron expression or a command — the admin page is read-only.
    const admin = await app.login(users.admin);
    const page = await app.page('/admin/scheduler', admin);
    assert.equal(page.res.status, 200);
    assert.doesNotMatch(page.html, /<input[^>]+name=["'](job|schedule|cron|command)["']/i, 'the scheduler admin page must not accept a job name, schedule or command from a form');
    const adminRoute = (await app.routes()).routes.find((r) => r.method === 'GET' && r.path === '/admin/scheduler');
    assert.ok(adminRoute, 'the scheduler admin page must be registered through the route registry');
    assert.equal(adminRoute!.auth, 'role:admin', 'only administrators may see job status');

    const table = app.dbTables().find((n) => /scheduler_jobs/i.test(n));
    assert.ok(table, 'a jobs table must exist');
    for (const col of ['name', 'last_run_at', 'lock_until', 'last_error']) {
      assert.ok(app.dbColumns(table!).includes(col), `${table} lacks column ${col}`);
    }

    // The runner kicks a due job shortly after start (src/lib/scheduler.ts); give it a moment, then check every
    // row has run at least once and — crucially — left no lease behind, whether it succeeded or failed.
    const deadline = Date.now() + 15_000;
    let rows: { name: string; last_run_at: string | null; lock_until: string | null; run_count: number }[] = [];
    for (;;) {
      rows = app.dbAll(`SELECT name, last_run_at, lock_until, run_count FROM ${table}`);
      if (rows.length > 0 && rows.every((r) => r.last_run_at !== null)) break;
      if (Date.now() > deadline) break;
      await new Promise((r) => setTimeout(r, 500));
    }
    assert.ok(rows.length >= 1, 'at least one job must be registered');
    for (const row of rows) {
      assert.ok(row.last_run_at, `job "${row.name}" never ran`);
      assert.equal(row.lock_until, null, `job "${row.name}" left its lease held after running — two overlapping ticks could then run it at once`);
      assert.ok(row.run_count >= 1, `job "${row.name}" has a run_count of 0 despite having a last_run_at`);
    }
  });
});
