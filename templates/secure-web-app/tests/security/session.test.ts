/** Session management (contract §1.6): reference tokens, rotation, timeouts, revocation, re-authentication. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, sleep, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';

/** Shifts a stored timestamp (ISO string, epoch seconds or epoch milliseconds) by `deltaMs`, keeping its format. */
function shifted(value: unknown, deltaMs: number): string | number {
  if (typeof value === 'number') {
    return value > 1e12 ? value + deltaMs : Math.floor(value + deltaMs / 1000);
  }
  const asNumber = Number(value);
  if (typeof value === 'string' && value !== '' && Number.isFinite(asNumber)) {
    return String(asNumber > 1e12 ? asNumber + deltaMs : Math.floor(asNumber + deltaMs / 1000));
  }
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) throw new Error(`cannot parse timestamp ${String(value)}`);
  return new Date(d.getTime() + deltaMs).toISOString();
}

describe('session', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  test('V7.2.3 session ids are 256-bit CSPRNG references stored only as hashes', async () => {
    const a = await app.login(users.member);
    const b = await app.login(users.member);
    const sidA = a.sessionId()!;
    const sidB = b.sessionId()!;
    assert.notEqual(sidA, sidB, 'two logins must produce different session ids');
    for (const sid of [sidA, sidB]) {
      assert.match(sid, /^[A-Za-z0-9_-]+$/, 'session id must be base64url');
      assert.ok(Buffer.from(sid, 'base64url').length >= 32, `session id must encode at least 32 random bytes (got ${sid.length} chars)`);
      assert.equal(app.dbContains(sid), false, 'the raw session id must not be stored in the database');
    }
    const rows = app.dbAll<{ id_hash: string }>('SELECT id_hash FROM sessions');
    assert.ok(rows.length >= 2, 'sessions table must hold the server-side sessions');
    for (const row of rows) {
      assert.ok(/^[0-9a-f]{64}$/i.test(row.id_hash) || /^[A-Za-z0-9+/=_-]{43,44}$/.test(row.id_hash), `id_hash must be an HMAC-SHA256 digest: ${row.id_hash}`);
    }
  });

  test('V7.2.4 a new session id is issued on login and the pre-login id is not upgraded', async () => {
    const jar = new CookieJar();
    const before = await app.fetch(paths.login, { jar });
    await before.text();
    const preLogin = jar.sessionId();
    await app.login(users.member, { jar });
    const postLogin = jar.sessionId()!;
    assert.ok(postLogin, 'login must set a session cookie');
    assert.notEqual(postLogin, preLogin, 'login must rotate the session id');
    if (preLogin) {
      const old = new CookieJar();
      old.cookies.set('sid', preLogin);
      assert.equal(await app.isAuthenticated(old), false, 'the pre-login id must not be authenticated');
    }
  });

  test('V7.3.1 an idle session expires: the server rejects it once the inactivity timeout has passed', async () => {
    const jar = await app.login(users.member);
    assert.equal(await app.isAuthenticated(jar), true);
    const userId = app.userId(users.member);
    const idleMinutes = Number(app.env.SESSION_IDLE_MINUTES ?? 30);
    const rows = app.dbAll<{ id_hash: string; last_seen_at: unknown; expires_at: unknown }>(
      'SELECT id_hash, last_seen_at, expires_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL',
      userId,
    );
    assert.ok(rows.length >= 1);
    for (const row of rows) {
      const past = -(idleMinutes + 1) * 60_000;
      app.dbRun('UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id_hash = ?', shifted(row.last_seen_at, past), shifted(row.expires_at, past), row.id_hash);
    }
    assert.equal(await app.isAuthenticated(jar), false, 'a session past its idle timeout must be rejected server-side');
  });

  test('V7.3.2 a session older than the absolute lifetime is rejected even when active', async () => {
    const jar = await app.login(users.member2);
    assert.equal(await app.isAuthenticated(jar), true);
    const userId = app.userId(users.member2);
    const absoluteHours = Number(app.env.SESSION_ABSOLUTE_HOURS ?? 12);
    const rows = app.dbAll<{ id_hash: string; created_at: unknown }>('SELECT id_hash, created_at FROM sessions WHERE user_id = ? AND revoked_at IS NULL', userId);
    assert.ok(rows.length >= 1);
    for (const row of rows) {
      app.dbRun('UPDATE sessions SET created_at = ? WHERE id_hash = ?', shifted(row.created_at, -(absoluteHours + 1) * 3_600_000), row.id_hash);
    }
    assert.equal(await app.isAuthenticated(jar), false, 'a session past its absolute lifetime must be rejected server-side');
  });

  test('V7.4.1 logout invalidates the session on the server', async () => {
    const jar = await app.login(users.member);
    const copy = jar.clone();
    const res = await app.logout(jar);
    await res.text();
    assert.ok(isRedirect(res) || res.status === 200, `logout answered ${res.status}`);
    assert.equal(await app.isAuthenticated(copy), false, 'the old cookie must be dead after logout');
  });

  test('V7.4.2 disabling an account terminates all of its sessions', async () => {
    const victim = await app.login(users.staff);
    const victim2 = await app.login(users.staff);
    const admin = await app.login(users.admin);
    const id = app.userId(users.staff);
    const res = await app.submitForm(paths.adminUserDisable(String(id)), { [fields.reason]: 'security test' }, admin, { csrfFrom: paths.adminUsers });
    const body = await res.text();
    assert.ok(res.status < 400, `disable failed: ${res.status} ${body.slice(0, 200)}`);
    assert.equal(await app.isAuthenticated(victim), false, 'session 1 must be terminated when the account is disabled');
    assert.equal(await app.isAuthenticated(victim2), false, 'session 2 must be terminated when the account is disabled');
    assert.equal(await app.canLogin(users.staff, app.password), false, 'a disabled account must not log in');
  });

  test('V7.4.3 changing the password offers "log out everywhere" and it terminates the other sessions', async () => {
    const current = await app.login(users.member);
    const other = await app.login(users.member);
    const newPassword = `${app.password}-rotated-1`;
    const res = await app.submitForm(
      paths.changePassword,
      { [fields.currentPassword]: app.password, [fields.newPassword]: newPassword, [fields.logoutEverywhere]: '1' },
      current,
    );
    const body = await res.text();
    assert.ok(res.status < 400, `password change failed: ${res.status} ${body.slice(0, 200)}`);
    assert.equal(await app.isAuthenticated(other), false, 'the other session must be terminated');
    const stillIn = await app.isAuthenticated(current);
    if (!stillIn) {
      // Acceptable: the app may end every session including the current one. The new password must work.
      assert.equal(await app.canLogin(users.member, newPassword), true);
    }
    // restore the shared password for the remaining tests
    const jar = stillIn ? current : await app.login(users.member, { password: newPassword });
    const back = await app.submitForm(paths.changePassword, { [fields.currentPassword]: newPassword, [fields.newPassword]: app.password }, jar);
    await back.text();
    assert.ok(back.status < 400, 'restoring the password failed');
  });

  test('V7.4.5 an administrator can terminate all sessions of a user', async () => {
    const s1 = await app.login(users.member2);
    const s2 = await app.login(users.member2);
    const admin = await app.login(users.admin);
    const since = new Date().toISOString();
    const id = app.userId(users.member2);
    const res = await app.submitForm(paths.adminUserRevokeSessions(String(id)), {}, admin, { csrfFrom: paths.adminUsers });
    const body = await res.text();
    assert.ok(res.status < 400, `revoke failed: ${res.status} ${body.slice(0, 200)}`);
    assert.equal(await app.isAuthenticated(s1), false);
    assert.equal(await app.isAuthenticated(s2), false);
    assert.equal(await app.isAuthenticated(admin), true, "the admin's own session stays");
    const events = await app.waitForEvent('session.revoked', since);
    assert.ok(events.length >= 1, 'session.revoked event must be emitted');
  });

  test('V7.5.1 changing the account email requires recent re-authentication', async () => {
    const jar = await app.login(users.member);
    const attempt = await app.submitForm(paths.changeEmail, { [fields.email]: 'member-renamed@test.local' }, jar);
    await attempt.text();
    const rejected = attempt.status === 401 || attempt.status === 403 || (isRedirect(attempt) && /reauth|password|verify|confirm/i.test(locationOf(attempt)));
    assert.ok(rejected, `email change without re-authentication must be refused (got ${attempt.status} -> ${locationOf(attempt)})`);
    assert.ok(app.userByEmail(users.member), 'the email must be unchanged');
    assert.equal(app.userByEmail('member-renamed@test.local'), undefined);

    const re = await app.reauth(jar);
    const reBody = await re.text();
    assert.ok(re.status < 400, `re-authentication failed: ${re.status} ${reBody.slice(0, 200)}`);
    const change = await app.submitForm(paths.changeEmail, { [fields.email]: 'member-renamed@test.local' }, jar);
    const changeBody = await change.text();
    assert.ok(change.status < 400, `email change after re-authentication failed: ${change.status} ${changeBody.slice(0, 200)}`);
    // Revert (a second re-auth is still within the 5 minute window).
    const revert = await app.submitForm(paths.changeEmail, { [fields.email]: users.member }, jar);
    await revert.text();
    assert.ok(app.userByEmail(users.member), 'the email change must be persisted (and reverted for later tests)');
  });

  test('V7.5.2 users can view their active sessions and terminate one of them', async () => {
    const mine = await app.login(users.member);
    const other = await app.login(users.member);
    const { res, html } = await app.page(paths.sessions, mine);
    assert.equal(res.status, 200, 'sessions page must render for a signed-in user');
    const actions = [...html.matchAll(/action=["']\/account\/sessions\/([^/"']+)\/revoke["']/g)].map((m) => m[1]!);
    assert.ok(actions.length >= 1, 'the sessions page must offer a revoke action per session');
    // Revoke every listed session except the current one; the other login must be gone afterwards.
    let revoked = 0;
    for (const id of actions) {
      const r = await app.submitForm(paths.sessionRevoke(id), {}, mine, { csrfFrom: paths.sessions });
      await r.text();
      if (r.status < 400) revoked++;
      if (!(await app.isAuthenticated(mine))) break;
    }
    assert.ok(revoked >= 1, 'at least one session must be revocable');
    assert.equal(await app.isAuthenticated(other), false, 'the revoked session must be terminated');
  });

  test('V7.1.2 the concurrent session cap is enforced: the oldest session is revoked', async () => {
    const max = Number(app.env.SESSION_MAX_CONCURRENT ?? 5);
    const jars: CookieJar[] = [];
    for (let i = 0; i <= max; i++) {
      jars.push(await app.login(users.member2));
      await sleep(20);
    }
    assert.equal(await app.isAuthenticated(jars[0]!), false, `the oldest session must be revoked once ${max + 1} sessions exist`);
    assert.equal(await app.isAuthenticated(jars[jars.length - 1]!), true, 'the newest session must be valid');
  });
});
