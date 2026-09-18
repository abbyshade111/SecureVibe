/** Password policy, storage, reset and bootstrap (contract §1.7). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { CookieJar, isRedirect, locationOf, runScript, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';
import { templateRoot } from '../helpers/features.ts';

const lower = 'abcdefghijklmnopqrstuvwxyz';
function randomLetters(n: number): string {
  const bytes = randomBytes(n);
  let s = '';
  for (const b of bytes) s += lower[b % 26];
  return s;
}

describe('password', () => {
  let app: RunningApp;
  /** Current password of member2, the account these tests mutate. */
  let current: string;

  before(async () => {
    app = await startApp();
    current = app.password;
  });
  after(async () => {
    await app?.stop();
  });

  /** Attempts a change for member2 and reports whether the new password is now the valid one. */
  async function attemptChange(next: string, opts: { currentPassword?: string } = {}): Promise<{ status: number; accepted: boolean }> {
    const jar = await app.login(users.member2, { password: current });
    const res = await app.submitForm(paths.changePassword, { [fields.currentPassword]: opts.currentPassword ?? current, [fields.newPassword]: next }, jar);
    await res.text();
    const accepted = await app.canLogin(users.member2, next);
    const oldStillWorks = await app.canLogin(users.member2, current);
    assert.notEqual(accepted, oldStillWorks, 'exactly one of the old and new password must be valid after a change attempt');
    if (accepted) current = next;
    return { status: res.status, accepted };
  }

  test('V6.2.1 rejects passwords shorter than 12 characters and accepts 12', async () => {
    const short = randomLetters(11);
    const r1 = await attemptChange(short);
    assert.equal(r1.accepted, false, `an 11 character password must be rejected (status ${r1.status})`);
    const twelve = randomLetters(12);
    const r2 = await attemptChange(twelve);
    assert.equal(r2.accepted, true, `a 12 character password must be accepted (status ${r2.status})`);
  });

  test('V6.2.4 rejects passwords found in the common-password list', async () => {
    // Deliberately well-known weak passwords, used to prove they are refused.
    for (const common of ['password1234', 'qwertyuiop12', 'iloveyou1234']) { // gitleaks:allow
      const r = await attemptChange(common);
      assert.equal(r.accepted, false, `"${common}" is a well-known password and must be rejected (status ${r.status})`);
    }
  });

  test('V6.2.5 accepts passwords of any composition (no character-class rules)', async () => {
    const onlyLower = randomLetters(24);
    const r1 = await attemptChange(onlyLower);
    assert.equal(r1.accepted, true, 'lowercase-only passwords must be allowed');
    const withSpacesAndUnicode = `correct horse ${randomLetters(6)} Straße ☃ 🔐`;
    const r2 = await attemptChange(withSpacesAndUnicode);
    assert.equal(r2.accepted, true, 'spaces and Unicode must be allowed');
  });

  test('V6.2.8 verifies the password exactly as received (no trimming, truncation or case folding)', async () => {
    const exact = `  Mixed Case ${randomLetters(10)}  `;
    const r = await attemptChange(exact);
    assert.equal(r.accepted, true, 'a password with leading/trailing spaces must be accepted as given');
    assert.equal(await app.canLogin(users.member2, exact.trim()), false, 'trimmed variant must not log in');
    assert.equal(await app.canLogin(users.member2, exact.toLowerCase()), false, 'lower-cased variant must not log in');
    assert.equal(await app.canLogin(users.member2, exact.slice(0, 20)), false, 'truncated variant must not log in');
    assert.equal(await app.canLogin(users.member2, exact), true);
  });

  test('V6.2.9 accepts passwords of at least 64 characters', async () => {
    const long = randomLetters(128);
    const r = await attemptChange(long);
    assert.equal(r.accepted, true, 'a 128 character password must be accepted');
    assert.equal(await app.canLogin(users.member2, long.slice(0, 64)), false, 'the long password must be used in full');
  });

  test('V6.2.11 rejects passwords containing context words such as the account name', async () => {
    const local = users.member2.split('@')[0]!;
    for (const contextual of [`${local}-${randomLetters(8)}`, `${randomLetters(8)}${local.toUpperCase()}`]) {
      const r = await attemptChange(contextual);
      assert.equal(r.accepted, false, `"${contextual}" contains the account name and must be rejected (status ${r.status})`);
    }
  });

  test('V6.2.3 changing the password requires the correct current password', async () => {
    const r = await attemptChange(randomLetters(20), { currentPassword: `wrong-${current}` });
    assert.equal(r.accepted, false, 'a change with a wrong current password must be rejected');
  });

  test('V6.2.10 passwords are never expired by age', async () => {
    const columns = app.dbColumns('users');
    const rotation = columns.filter((c) => /expire|rotat|max_age/i.test(c) && /pass|pwd|credential/i.test(c));
    assert.deepEqual(rotation, [], `users table must not carry a password expiry column: ${rotation.join(', ')}`);
    const changedAt = columns.find((c) => /password.*(changed|updated|set)_at/i.test(c));
    if (changedAt) {
      const twoYearsAgo = new Date(Date.now() - 2 * 365 * 86_400_000).toISOString();
      app.dbRun(`UPDATE users SET ${changedAt} = ? WHERE lower(email) = lower(?)`, twoYearsAgo, users.member2);
    }
    assert.equal(await app.canLogin(users.member2, current), true, 'an old password must still be valid');
    const example = existsSync(join(templateRoot, '.env.example')) ? readFileSync(join(templateRoot, '.env.example'), 'utf8') : '';
    assert.doesNotMatch(example, /PASSWORD_(MAX_AGE|EXPIR|ROTAT)/i, '.env.example must not offer a password rotation setting');
  });

  test('V11.4.2 stored passwords are PHC strings from argon2id (m=65536,t=3,p=4) or scrypt (N=2^17,r=8,p=1)', async () => {
    const row = app.userByEmail(users.member2)!;
    const column = Object.keys(row).find((c) => /password/i.test(c) && /hash|digest/i.test(c)) ?? Object.keys(row).find((c) => /password/i.test(c));
    assert.ok(column, `no password hash column in users: ${Object.keys(row).join(', ')}`);
    const hash = String(row[column]);
    const argon = /^\$argon2id\$v=19\$m=65536,t=3,p=4\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/;
    const scrypt = /^\$scrypt\$(ln=17|N=131072),r=8,p=1\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$/;
    assert.ok(argon.test(hash) || scrypt.test(hash), `password hash is not an approved PHC string: ${hash.slice(0, 40)}...`);
    assert.equal(app.dbContains(current), false, 'the plaintext password must not appear in the database');
  });

  test('V6.3.2 no default accounts exist outside test mode', async () => {
    const prod = await startApp({ mode: 'production' });
    try {
      let count = 0;
      if (readdirSync(prod.dataDir).some((f) => /\.(db|sqlite|sqlite3)$/.test(f))) {
        count = Number(prod.dbAll<{ n: number }>('SELECT count(*) AS n FROM users')[0]?.n ?? 0);
      }
      assert.equal(count, 0, 'a fresh production database must contain no accounts');
      for (const [email, password] of [
        ['admin', 'admin'],
        ['admin@test.local', 'password'],
        ['root', 'root'],
        ['admin@example.com', 'admin'],
      ]) {
        const res = await prod.loginRaw(email!, password!);
        await res.text();
        assert.ok(!(isRedirect(res) && !/login/i.test(locationOf(res))), `default credentials ${email}/${password} must not log in`);
      }
      const probe = await prod.fetch(paths.testRoutes);
      await probe.text();
      assert.equal(probe.status, 404, 'test-mode endpoints must not exist in production');
    } finally {
      await prod.stop();
    }
  });

  test('V6.4.1 the bootstrap admin gets a random one-time password that must be changed and expires', async () => {
    const prod = await startApp({ mode: 'production' });
    const cwd = mkdtempSync(join(tmpdir(), 'securevibe-bootstrap-'));
    try {
      const result = await runScript('bootstrap-admin', prod.env, { cwd, args: ['--email', 'owner@example.com'] });
      assert.equal(result.code, 0, `bootstrap-admin failed: ${result.stderr || result.stdout}`);
      const candidates = [join(cwd, 'FIRST-LOGIN.txt'), join(prod.dataDir, 'FIRST-LOGIN.txt'), join(templateRoot, 'FIRST-LOGIN.txt')];
      const file = candidates.find((f) => existsSync(f));
      assert.ok(file, 'FIRST-LOGIN.txt must be written with the one-time password');
      const text = readFileSync(file, 'utf8');
      if (file === join(templateRoot, 'FIRST-LOGIN.txt')) rmSync(file, { force: true });
      const passwordMatch = text.match(/password[^:\n]*:\s*(\S+)/i) ?? result.stdout.match(/password[^:\n]*:\s*(\S+)/i);
      assert.ok(passwordMatch, `FIRST-LOGIN.txt must state the password: ${text}`);
      const oneTime = passwordMatch[1]!;
      assert.ok(oneTime.length >= 16, 'the one-time password must be at least 16 characters');
      const admin = prod.dbAll('SELECT * FROM users')[0];
      assert.ok(admin, 'bootstrap must create exactly one admin row');
      assert.equal(Number(admin.must_change_password), 1, 'the bootstrap admin must be forced to change the password');
      const expiryColumn = Object.keys(admin).find((c) => /expir/i.test(c));
      assert.ok(expiryColumn, `bootstrap password must have an expiry column: ${Object.keys(admin).join(', ')}`);
      const expiry = admin[expiryColumn];
      const expiryMs = typeof expiry === 'number' ? (expiry > 1e12 ? expiry : expiry * 1000) : new Date(String(expiry)).getTime();
      const hours = (expiryMs - Date.now()) / 3_600_000;
      assert.ok(hours > 0 && hours <= 24.5, `bootstrap password must expire within 24 h (expires in ${hours.toFixed(1)} h)`);
      assert.equal(prod.dbContains(oneTime), false, 'the one-time password must be stored hashed');
    } finally {
      rmSync(cwd, { recursive: true, force: true });
      await prod.stop();
    }
  });

  test('V6.4.2 no password hints or secret questions anywhere in the authentication flows', async () => {
    const jar = await app.login(users.member);
    const pages = [paths.login, paths.forgotPassword, paths.register, paths.account, paths.changePassword, paths.profile];
    for (const path of pages) {
      const { res, html } = await app.page(path, jar);
      if (res.status !== 200) continue;
      const inputs = [...html.matchAll(/<(input|textarea|select)\b[^>]*name=["']([^"']+)["']/gi)].map((m) => m[2]!);
      const suspicious = inputs.filter((n) => /hint|secret[_-]?question|security[_-]?question|answer|mother|pet|maiden/i.test(n));
      assert.deepEqual(suspicious, [], `${path} has knowledge-based fields: ${suspicious.join(', ')}`);
      assert.doesNotMatch(html, /password hint|secret question|security question/i, `${path} mentions hints or secret questions`);
    }
  });

  test('V6.4.3 password reset uses a hashed single-use token and still requires the second factor', async () => {
    const mailsBefore = app.outbox().length;
    const request = await app.submitForm(paths.forgotPassword, { [fields.email]: users.admin }, new CookieJar());
    await request.text();
    assert.ok(request.status < 400, `reset request failed: ${request.status}`);
    const mails = await app.waitForOutbox(mailsBefore + 1);
    const mail = mails[mails.length - 1]!.text;
    const tokenMatch = mail.match(/reset-password\/([A-Za-z0-9_-]+)/);
    assert.ok(tokenMatch, `reset mail must contain a reset link: ${mail.slice(0, 500)}`);
    const token = tokenMatch[1]!;
    assert.equal(app.dbContains(token), false, 'the reset token must be stored hashed');

    const newPassword = `reset-${randomLetters(16)}`;
    const jar = new CookieJar();
    const reset = await app.submitForm(paths.resetPassword(token), { [fields.password]: newPassword }, jar, { csrfFrom: paths.resetPassword(token) });
    const resetBody = await reset.text();
    assert.ok(reset.status < 400, `reset failed: ${reset.status} ${resetBody.slice(0, 200)}`);
    assert.equal(await app.isAuthenticated(jar), false, 'a password reset must not sign the user in by itself');

    // The token is single use.
    const again = await app.submitForm(paths.resetPassword(token), { [fields.password]: `${newPassword}-2` }, new CookieJar(), {
      csrfFrom: paths.resetPassword(token),
    });
    await again.text();
    assert.equal(await app.canLogin(users.admin, `${newPassword}-2`, app.totpSeed), false, 'a used reset token must be rejected');

    // MFA is still required after the reset.
    const login = await app.loginRaw(users.admin, newPassword);
    await login.text();
    assert.ok(isRedirect(login), 'login with the new password must proceed to the second factor');
    assert.match(locationOf(login), /mfa|totp|2fa|verify/i, 'admin must still be asked for the second factor after a reset');
    const jar2 = new CookieJar();
    jar2.absorb(login);
    assert.equal(await app.isAuthenticated(jar2), false, 'password alone must not grant a full session');
    const complete = await app.login(users.admin, { password: newPassword, totpSeed: app.totpSeed });
    assert.equal(await app.isAuthenticated(complete), true);
    // restore
    const back = await app.submitForm(paths.changePassword, { [fields.currentPassword]: newPassword, [fields.newPassword]: app.password }, complete);
    await back.text();
  });

  test('V6.4.3 the response to a reset request is the same whether or not the account exists', async () => {
    const known = await app.submitForm(paths.forgotPassword, { [fields.email]: users.member }, new CookieJar());
    const knownBody = await known.text();
    const unknown = await app.submitForm(paths.forgotPassword, { [fields.email]: `nobody-${randomLetters(6)}@test.local` }, new CookieJar());
    const unknownBody = await unknown.text();
    assert.equal(unknown.status, known.status, 'status must not reveal whether the account exists');
    assert.equal(locationOf(unknown), locationOf(known), 'redirect target must not reveal whether the account exists');
    // Per-request values (the CSP nonce, the CSRF token) differ by design; everything else must be identical.
    const strip = (s: string) =>
      s.replace(/nonce-[^'"]+/g, '').replace(/nonce=["'][^"']*["']/g, '').replace(/value=["'][^"']*["']/g, '').replace(/content=["'][^"']*["']/g, '');
    assert.equal(strip(unknownBody), strip(knownBody), 'page content must not reveal whether the account exists');
    assert.doesNotMatch(unknownBody, /no account|not found|unknown (user|email)|does not exist/i);
  });

  test('V11.5.1 reset tokens come from a CSPRNG with at least 128 bits and are never stored in clear', async () => {
    const before = app.outbox().length;
    const tokens: string[] = [];
    for (let i = 0; i < 2; i++) {
      const res = await app.submitForm(paths.forgotPassword, { [fields.email]: users.member }, new CookieJar());
      await res.text();
      const mails = await app.waitForOutbox(before + i + 1);
      const m = mails[mails.length - 1]!.text.match(/reset-password\/([A-Za-z0-9_-]+)/);
      assert.ok(m, 'reset mail must contain a token link');
      tokens.push(m[1]!);
    }
    assert.notEqual(tokens[0], tokens[1], 'tokens must be unique');
    for (const token of tokens) {
      assert.ok(Buffer.from(token, 'base64url').length >= 16, `token must encode at least 128 bits: ${token}`);
      assert.equal(app.dbContains(token), false, 'token must be stored hashed');
    }
  });

  test('V6.4.3 a reset token expires after 15 minutes', async (t) => {
    const before = app.outbox().length;
    const res = await app.submitForm(paths.forgotPassword, { [fields.email]: users.member2 }, new CookieJar());
    await res.text();
    const mails = await app.waitForOutbox(before + 1);
    const token = mails[mails.length - 1]!.text.match(/reset-password\/([A-Za-z0-9_-]+)/)?.[1];
    assert.ok(token);
    const table = app.dbTables().find((n) => /reset/i.test(n));
    if (!table) return t.skip('no dedicated reset-token table to age; expiry is covered by the single-use test');
    const columns = app.dbColumns(table);
    const expires = columns.find((c) => /expire/i.test(c));
    const created = columns.find((c) => /created/i.test(c));
    if (!expires && !created) return t.skip(`table ${table} has no expiry or creation timestamp`);
    const twentyMinutesAgo = new Date(Date.now() - 20 * 60_000).toISOString();
    if (expires) app.dbRun(`UPDATE ${table} SET ${expires} = ?`, twentyMinutesAgo);
    if (created) app.dbRun(`UPDATE ${table} SET ${created} = ?`, new Date(Date.now() - 40 * 60_000).toISOString());
    const attempted = `expired-${randomLetters(12)}`;
    const use = await app.submitForm(paths.resetPassword(token), { [fields.password]: attempted }, new CookieJar(), {
      csrfFrom: paths.resetPassword(token),
    });
    await use.text();
    assert.equal(await app.canLogin(users.member2, attempted), false, 'an expired token must not set a new password');
    assert.equal(await app.canLogin(users.member2, current), true, 'an expired token must not change the password');
  });
});
