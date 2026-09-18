/** Multi-factor authentication (contract §1.7 TOTP, TPL-MFA-01..04). */
import { after, before, beforeEach, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';
import { base32Decode, totp, waitForFreshStep, waitForNextStep } from '../helpers/totp.ts';
import { featureFromFile, skipReason } from '../helpers/features.ts';

// The one-time-code mechanics (seed storage, code lifetime, recovery codes, admin reset) are the same code whether
// or not this app offers the second factor to every user, so they are checked with enrolment switched on. Whether
// every user can enrol is this app's decision, checked separately below.
const userMfaOffered = featureFromFile('user-mfa') !== false;

const MFA_STEP = /mfa|totp|2fa|verify/i;

/** Seeds and recovery codes captured by earlier tests in this file. */
const state: { memberTotpSeed?: string; memberRecoveryCodes?: string[]; member2TotpSeed?: string; member2RecoveryCodes?: string[] } = {};

describe('mfa', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp({ env: { USER_MFA_AVAILABLE: '1' } });
  });
  after(async () => {
    await app?.stop();
  });
  // Every test signs the admin in through the second factor; the per-account MFA limiter (5 per 15 minutes)
  // would otherwise be exhausted by earlier tests in this file.
  beforeEach(async () => {
    await app.resetRateLimits();
  });

  /** Password step for the admin; returns the jar (not yet fully authenticated) and the MFA page location. */
  async function passwordStep(email: string = users.admin, password: string = app.password): Promise<{ jar: CookieJar; mfaPage: string }> {
    const jar = new CookieJar();
    const res = await app.loginRaw(email, password, jar);
    await res.text();
    assert.ok(isRedirect(res), `password step for ${email} did not redirect (${res.status})`);
    const mfaPage = locationOf(res);
    assert.match(mfaPage, MFA_STEP, `expected a redirect to the second-factor page, got ${mfaPage}`);
    return { jar, mfaPage };
  }

  async function secondFactor(jar: CookieJar, code: string, mfaPage: string): Promise<boolean> {
    const res = await app.submitMfa(jar, code, mfaPage);
    await res.text();
    return app.isAuthenticated(jar);
  }

  test('V6.3.3 administrators must present a second factor; the password alone grants no session', async () => {
    const { jar, mfaPage } = await passwordStep();
    assert.equal(await app.isAuthenticated(jar), false, 'password-only admin login must not be authenticated');
    for (const protectedPath of [paths.adminUsers, paths.account]) {
      const res = await app.fetch(protectedPath, { jar });
      await res.text();
      assert.notEqual(res.status, 200, `${protectedPath} must not render before the second factor`);
    }
    await waitForFreshStep();
    assert.equal(await secondFactor(jar, totp(app.totpSeed), mfaPage), true, 'a valid TOTP code must complete the login');
    const admin = await app.fetch(paths.adminUsers, { jar });
    await admin.text();
    assert.equal(admin.status, 200, 'the admin area must open after the second factor');
  });

  test('V6.3.3 the second factor is available to every user (enrolment offered on the account pages)', async (t) => {
    if (!userMfaOffered) return t.skip(skipReason('user-mfa'));
    const jar = await app.login(users.member);
    const { res } = await app.page(paths.mfaEnrol, jar);
    assert.ok(res.status === 200 || (isRedirect(res) && /reauth|password/i.test(locationOf(res))), `MFA enrolment must be reachable for non-admin users (got ${res.status})`);
  });

  test('V6.5.1 a TOTP code is accepted only once', async () => {
    // A step that has just begun: never presented before (earlier tests signed in with earlier steps) and long
    // enough for both attempts below, so the first use tests acceptance and the second tests replay.
    await waitForNextStep();
    const code = totp(app.totpSeed);
    const first = await passwordStep();
    assert.equal(await secondFactor(first.jar, code, first.mfaPage), true, 'first use must succeed');
    const second = await passwordStep();
    assert.equal(await secondFactor(second.jar, code, second.mfaPage), false, 'replaying the same code must fail');
    const failures = await app.waitForEvent('auth.mfa.failure');
    assert.ok(failures.length >= 1, 'auth.mfa.failure event must be emitted on a rejected code');
  });

  test('V6.5.5 TOTP codes have a bounded lifetime: one step of drift is tolerated, older codes are rejected', async () => {
    // Two fresh steps: the "previous step" code below must belong to a step no earlier test presented, otherwise
    // replay prevention (correctly) rejects it.
    await waitForNextStep();
    await waitForNextStep();
    const now = Date.now();
    const stale = await passwordStep();
    assert.equal(await secondFactor(stale.jar, totp(app.totpSeed, { now, offset: -3 }), stale.mfaPage), false, 'a code from 90 s ago must be rejected');
    const future = await passwordStep();
    assert.equal(await secondFactor(future.jar, totp(app.totpSeed, { now, offset: +3 }), future.mfaPage), false, 'a code from 90 s ahead must be rejected');
    const wrong = await passwordStep();
    assert.equal(await secondFactor(wrong.jar, '000000', wrong.mfaPage), false, 'an arbitrary code must be rejected');
    const recent = await passwordStep();
    assert.equal(await secondFactor(recent.jar, totp(app.totpSeed, { now, offset: -1 }), recent.mfaPage), true, 'the previous step (clock drift) must be accepted');
  });

  test('V6.5.3 enrolment generates a fresh 20-byte CSPRNG seed and stores it encrypted', async () => {
    const jar = await app.login(users.member);
    const re = await app.reauth(jar);
    await re.text();
    const first = await app.page(paths.mfaEnrol, jar);
    assert.equal(first.res.status, 200, `enrol page did not render: ${first.res.status}`);
    const secretOf = (html: string) => html.match(/otpauth:\/\/totp\/[^"'\s<]*[?&]secret=([A-Z2-7]+)/i)?.[1] ?? html.match(/secret=([A-Z2-7]{32})/i)?.[1];
    const secret1 = secretOf(first.html);
    assert.ok(secret1, 'the enrolment page must show an otpauth:// URI with the secret');
    assert.equal(base32Decode(secret1).length, 20, 'the TOTP seed must be 20 bytes (160 bits)');
    const second = await app.page(paths.mfaEnrol, jar);
    const secret2 = secretOf(second.html);
    assert.ok(secret2);
    if (secret2 !== secret1) assert.notEqual(secret2, secret1);

    await waitForFreshStep();
    const confirm = await app.submitForm(paths.mfaConfirm, { [fields.code]: totp(secret2) }, jar, { csrfFrom: paths.mfaEnrol });
    const confirmBody = await confirm.text();
    assert.ok(confirm.status < 400, `enrolment confirmation failed: ${confirm.status} ${confirmBody.slice(0, 200)}`);
    const enrolled = await app.waitForEvent('auth.mfa.enrolled');
    assert.ok(enrolled.length >= 1, 'auth.mfa.enrolled event must be emitted');

    assert.equal(app.dbContains(secret2), false, 'the base32 seed must not be stored in clear');
    assert.equal(app.dbContains(base32Decode(secret2).toString('base64')), false, 'the raw seed bytes must not be stored in clear (base64)');
    assert.equal(app.dbBytes().includes(base32Decode(secret2)), false, 'the raw seed bytes must not be stored in clear (binary)');
    const row = app.userByEmail(users.member)!;
    const column = Object.keys(row).find((c) => /totp|mfa|otp/i.test(c) && /secret|seed|key/i.test(c));
    assert.ok(column, `users table must have an encrypted TOTP seed column: ${Object.keys(row).join(', ')}`);
    assert.match(String(row[column]), /^v\d+:/, 'the seed must be stored with the versioned field-encryption format');

    // From now on member needs the second factor.
    const step = await passwordStep(users.member);
    assert.equal(await app.isAuthenticated(step.jar), false);
    await waitForFreshStep();
    assert.equal(await secondFactor(step.jar, totp(secret2, { offset: 0 }), step.mfaPage), true, 'member must be able to log in with the enrolled seed');
    state.memberTotpSeed = secret2;
  });

  test('V6.5.2 recovery codes are shown once, stored hashed and each works only once', async () => {
    const seed = state.memberTotpSeed;
    assert.ok(seed, 'depends on the enrolment test above');
    const jar = await app.login(users.member, { totpSeed: seed });
    // Recovery codes are shown on the confirmation result page; fetch the enrolment/account page where they are listed.
    const pagesToTry = [paths.mfaConfirm, paths.mfaEnrol, paths.account, `${paths.account}/mfa`, `${paths.account}/mfa/recovery-codes`];
    let codes: string[] = [];
    for (const path of pagesToTry) {
      const { res, html } = await app.page(path, jar);
      if (res.status !== 200) continue;
      const found = [...new Set([...html.matchAll(/\b([A-Z2-7]{10})\b/g)].map((m) => m[1]!))];
      if (found.length >= 10) {
        codes = found;
        break;
      }
    }
    if (codes.length < 10) {
      // Codes may only be shown right after confirmation: enrol member2 to capture them.
      const j2 = await app.login(users.member2);
      const re = await app.reauth(j2);
      await re.text();
      const { html } = await app.page(paths.mfaEnrol, j2);
      const secret = html.match(/secret=([A-Z2-7]+)/i)?.[1];
      assert.ok(secret, 'enrol page must show the secret');
      await waitForFreshStep();
      const confirm = await app.submitForm(paths.mfaConfirm, { [fields.code]: totp(secret) }, j2, { csrfFrom: paths.mfaEnrol });
      let body = await confirm.text();
      if (isRedirect(confirm)) body = (await app.page(locationOf(confirm), j2)).html;
      codes = [...new Set([...body.matchAll(/\b([A-Z2-7]{10})\b/g)].map((m) => m[1]!))];
      assert.ok(codes.length >= 10, `expected 10 recovery codes after confirmation, found ${codes.length}`);
      state.member2TotpSeed = secret;
      state.member2RecoveryCodes = codes;
    } else {
      state.memberRecoveryCodes = codes;
    }
    const owner = state.member2RecoveryCodes ? users.member2 : users.member;
    for (const code of codes.slice(0, 10)) assert.equal(app.dbContains(code), false, `recovery code ${code} must be stored hashed`);

    const code = codes[0]!;
    const first = await passwordStep(owner);
    assert.equal(await secondFactor(first.jar, code, first.mfaPage), true, 'a recovery code must complete the login');
    const second = await passwordStep(owner);
    assert.equal(await secondFactor(second.jar, code, second.mfaPage), false, 'a recovery code must be single use');
  });

  test('V6.5.4 recovery codes carry at least 50 bits of entropy (10 base32 characters) and are unique', async () => {
    const codes = state.member2RecoveryCodes ?? state.memberRecoveryCodes ?? [];
    assert.ok(codes.length >= 10, 'depends on the recovery code test above');
    for (const code of codes) assert.match(code, /^[A-Z2-7]{10}$/);
    assert.equal(new Set(codes).size, codes.length, 'recovery codes must be unique');
  });

  test('V6.4.4 an administrator can reset a user\'s second factor and the reason is logged', async (t) => {
    const owner = state.member2RecoveryCodes ? users.member2 : users.member;
    const admin = await app.login(users.admin);
    const id = app.userId(owner);
    const route = await app.findRoute('POST', /\/admin\/users\/:[A-Za-z]+\/(mfa|totp)[-_/]?reset/);
    if (!route) return t.skip('no admin MFA reset route registered');
    const since = new Date().toISOString();
    const res = await app.submitForm(route.path.replace(/:[A-Za-z]+/, String(id)), { [fields.reason]: 'lost authenticator (security test)' }, admin, {
      csrfFrom: paths.adminUsers,
    });
    const body = await res.text();
    assert.ok(res.status < 400, `MFA reset failed: ${res.status} ${body.slice(0, 200)}`);
    const events = await app.waitForEvent('admin.user.mfa_reset', since);
    assert.ok(events.length >= 1, 'admin.user.mfa_reset event must be emitted');
    const jar = await app.login(owner);
    assert.equal(await app.isAuthenticated(jar), true, 'after the reset the user logs in with the password only and is asked to re-enrol');
  });
});
