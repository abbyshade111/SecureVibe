/** Logging and audit (contract §1.9, TPL-LOG-01..05, MT-07). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CookieJar, runScript, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';
import { templateRoot } from '../helpers/features.ts';

const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

describe('logging', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  function eventLines(name?: string): Record<string, unknown>[] {
    return app.logLines().filter((l) => typeof l.event === 'string' && (name === undefined || l.event === name));
  }

  test('V16.2.1 every log entry is structured JSON with a UTC timestamp, request id, actor, route and outcome', async () => {
    const jar = new CookieJar();
    const failed = await app.loginRaw(users.member, 'definitely-the-wrong-password', jar);
    await failed.text();
    const ok = await app.login(users.member);
    assert.equal(await app.isAuthenticated(ok), true);
    await app.waitForEvent('auth.login.success');

    const lines = app.logLines();
    assert.ok(lines.length > 0, 'the log file must contain JSON lines');
    const failure = eventLines('auth.login.failure').at(-1);
    const success = eventLines('auth.login.success').at(-1);
    assert.ok(failure, 'auth.login.failure must be written to the log file');
    assert.ok(success, 'auth.login.success must be written to the log file');
    for (const entry of [failure, success]) {
      assert.match(String(entry.ts), ISO_UTC, `event ts must be a UTC ISO timestamp: ${String(entry.ts)}`);
      assert.ok(typeof entry.reqId === 'string' && entry.reqId.length >= 8, 'event must carry the request id');
      assert.ok(typeof entry.ip === 'string' && entry.ip.length > 0, 'event must carry the client ip');
      assert.ok(['success', 'failure', 'blocked'].includes(String(entry.outcome)), `outcome must be set: ${String(entry.outcome)}`);
    }
    assert.equal(failure.outcome, 'failure');
    assert.equal(success.outcome, 'success');
    assert.ok(success.userId !== undefined && success.userId !== null, 'a successful login must record the user id');
  });

  test('V16.3.1 authentication operations are logged with the factor used, including failures', async () => {
    await app.login(users.admin);
    const events = await app.waitForEvent('auth.login.success', undefined, (e) => e.factor === 'password+totp');
    assert.ok(events.length >= 1, 'admin login must be logged with factor password+totp');
    const passwordOnly = await app.eventsNamed('auth.login.success');
    assert.ok(passwordOnly.some((e) => e.factor === 'password'), 'member login must be logged with factor password');
    const failures = await app.eventsNamed('auth.login.failure');
    assert.ok(failures.length >= 1 && failures.every((e) => typeof e.reason === 'string'), 'login failures must carry a reason');

    const jar = await app.login(users.member);
    const res = await app.logout(jar);
    await res.text();
    assert.ok((await app.waitForEvent('auth.logout')).length >= 1, 'logout must be logged');
    const denied = await app.fetch(paths.adminUsers, { jar: await app.login(users.member) });
    await denied.text();
    assert.ok((await app.waitForEvent('authz.denied')).length >= 1, 'authorization denials must be logged');
  });

  test('V16.2.5 secrets are redacted: passwords, session ids, tokens and cookies never reach the log', async () => {
    const jar = await app.login(users.member);
    const text = app.logText();
    assert.ok(text.length > 0);
    assert.equal(text.includes(app.password), false, 'the password must not be logged');
    assert.equal(text.includes(jar.sessionId()!), false, 'the raw session id must not be logged');
    assert.equal(text.includes(app.env.SESSION_SECRET!), false, 'SESSION_SECRET must not be logged');
    assert.equal(text.includes(app.env.TOKEN_HMAC_KEY!), false, 'TOKEN_HMAC_KEY must not be logged');
    assert.equal(text.includes(app.env.FIELD_KEYS!.split(':')[1]!), false, 'field keys must not be logged');
    assert.equal(text.includes(app.totpSeed), false, 'the TOTP seed must not be logged');
    for (const line of app.logLines()) {
      for (const key of Object.keys(line)) {
        if (/password|cookie|set-cookie|authorization|secret|totp|token|apikey|api_key/i.test(key) && key !== 'event') {
          const v = line[key];
          assert.ok(v === '[Redacted]' || v === '***' || v === null || String(v).length <= 12 || String(v).includes('Redact'), `field ${key} is logged in clear: ${String(v)}`);
        }
      }
    }
  });

  test('V16.4.1 log entries are JSON-encoded so injected newlines and fake fields cannot forge entries', async () => {
    const forged = 'x\n{"event":"auth.login.success","userId":"forged","outcome":"success"}\r\n';
    const jar = new CookieJar();
    for (const email of [`${forged}@test.local`, `"${forged}"@test.local`, `member@test.local${forged}`]) {
      const res = await app.loginRaw(email, `pw${forged}`, jar);
      await res.text();
    }
    const raw = await app.fetch(`/nope${encodeURIComponent(forged)}`, { headers: { 'User-Agent': `agent ${forged.replace(/[\r\n]/g, ' ')}` } });
    await raw.text();
    const lines = app.logText().split('\n').filter((l) => l.trim() !== '');
    for (const line of lines) {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(line) as Record<string, unknown>;
      } catch {
        assert.fail(`a log line is not valid JSON (log injection): ${line.slice(0, 200)}`);
      }
      assert.notEqual(parsed.userId, 'forged', 'a forged entry was written');
      assert.ok(!line.startsWith('{"event":"auth.login.success","userId":"forged"'), 'injected text started a new log line');
    }
    assert.ok(lines.length > 0);
  });

  test('V16.4.2 audit chain: the audit table is hash-chained and the verify command detects tampering', async () => {
    const admin = await app.login(users.admin);
    const id = app.userId(users.member2);
    const res = await app.submitForm(paths.adminUserDisable(String(id)), { [fields.reason]: 'audit chain test' }, admin, { csrfFrom: paths.adminUsers });
    await res.text();
    await app.waitForEvent('admin.user.disabled');

    const rows = app.dbAll<{ hash: string; prev_hash: string | null }>('SELECT hash, prev_hash FROM audit_log ORDER BY rowid');
    assert.ok(rows.length >= 3, 'audit_log must contain the security events');
    for (let i = 0; i < rows.length; i++) {
      assert.match(rows[i]!.hash, /^[0-9a-f]{64}$/i, 'hash must be a SHA-256 hex digest');
      if (i > 0) assert.equal(rows[i]!.prev_hash, rows[i - 1]!.hash, `row ${i} does not chain to its predecessor`);
    }
    const verify = await runScript('audit-verify', app.env);
    assert.equal(verify.code, 0, `audit:verify must succeed on an intact chain: ${verify.stderr || verify.stdout}`);

    // Tamper with a row: either the table refuses updates (append-only) or verification must fail.
    let tampered = false;
    try {
      const r = app.dbRun("UPDATE audit_log SET event = 'tampered.event' WHERE rowid = (SELECT max(rowid) FROM audit_log)");
      tampered = Number(r.changes) > 0;
    } catch {
      tampered = false;
    }
    if (tampered) {
      const after = await runScript('audit-verify', app.env);
      assert.notEqual(after.code, 0, 'audit:verify must fail after a row was modified');
    } else {
      const del = (() => {
        try {
          return Number(app.dbRun('DELETE FROM audit_log WHERE rowid = (SELECT max(rowid) FROM audit_log)').changes);
        } catch {
          return 0;
        }
      })();
      assert.equal(del, 0, 'an append-only table must also refuse deletes');
    }
  });

  test('MT-07 audit records are tamper-evident, retained for at least a year and cover administrative actions', async () => {
    const retention = Number(app.env.AUDIT_RETENTION_DAYS ?? 400);
    assert.ok(retention >= 365, `AUDIT_RETENTION_DAYS must be at least 365 (is ${retention})`);
    const examplePath = join(templateRoot, '.env.example');
    if (existsSync(examplePath)) {
      const m = readFileSync(examplePath, 'utf8').match(/^AUDIT_RETENTION_DAYS=(\d+)/m);
      if (m) assert.ok(Number(m[1]) >= 365, `.env.example must keep audit logs for at least a year (is ${m[1]})`);
    }
    // Perform a harmless administrative action so the table is guaranteed to contain an admin.* record.
    const adminJar = await app.login(users.admin);
    const targetId = app.userId(users.member2);
    const revoke = await app.submitForm(`/admin/users/${targetId}/sessions/revoke`, {}, adminJar, { csrfFrom: paths.adminUsers });
    await revoke.text();
    assert.ok(revoke.status < 400, `the admin action must succeed (got ${revoke.status})`);
    await app.waitForEvent('admin.user.sessions_revoked');
    const adminEvents = app.dbAll<{ event: string }>("SELECT event FROM audit_log WHERE event LIKE 'admin.%'");
    assert.ok(adminEvents.length >= 1, 'administrative actions must be in the audit table');
    const columns = app.dbColumns('audit_log');
    for (const c of ['hash', 'prev_hash']) assert.ok(columns.includes(c), `audit_log lacks column ${c}`);
    assert.ok(existsSync(join(templateRoot, 'scripts', 'audit-verify.ts')), 'scripts/audit-verify.ts must exist');
    const viewer = await app.fetch(paths.adminAudit, { jar: await app.login(users.admin) });
    await viewer.text();
    assert.equal(viewer.status, 200, 'administrators must be able to view the audit log');
    const member = await app.fetch(paths.adminAudit, { jar: await app.login(users.member) });
    await member.text();
    assert.ok([401, 403, 404].includes(member.status), 'members must not read the audit log');
  });

  test('V16.3.2 validation rejections and anti-automation hits are logged as security events', async () => {
    const jar = await app.login(users.member);
    if (await app.featureEnabled('example')) {
      const res = await app.json('POST', paths.notesApi, { nope: 1 }, jar);
      await res.text();
      const events = await app.waitForEvent('validation.rejected');
      assert.ok(events.length >= 1, 'validation.rejected must be logged');
      assert.ok(events.every((e) => typeof e.route === 'string'), 'validation.rejected must name the route');
    }
    const res = await app.submitForm(paths.logout, {}, jar, { csrfToken: 'forged' });
    await res.text();
    assert.ok((await app.waitForEvent('csrf.rejected')).length >= 1, 'csrf.rejected must be logged');
  });
});
