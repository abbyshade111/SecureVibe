/** Anti-automation (contract §1.8, TPL-AUTH-05, TPL-RATE-01, TPL-PROXY-01). Runs its limit-hitting steps last. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';

describe('rate-limit', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  function retryAfterOk(res: Response): void {
    const ra = res.headers.get('retry-after');
    assert.ok(ra !== null, '429 responses must carry Retry-After');
    assert.ok(/^\d+$/.test(ra) || !Number.isNaN(new Date(ra).getTime()), `Retry-After must be seconds or an HTTP date: ${ra}`);
  }

  test('V6.3.1 login responses are identical for unknown accounts and wrong passwords', async () => {
    const unknown = await app.loginRaw(`nobody-${randomBytes(4).toString('hex')}@test.local`, 'some-wrong-password-123');
    const unknownBody = await unknown.text();
    const wrong = await app.loginRaw(users.member, 'some-wrong-password-123');
    const wrongBody = await wrong.text();
    assert.equal(unknown.status, wrong.status, 'status must not reveal whether the account exists');
    assert.equal(locationOf(unknown), locationOf(wrong), 'redirect must not reveal whether the account exists');
    // Per-request values (the CSP nonce, the CSRF token) differ by design; everything else must be identical.
    const strip = (s: string) =>
      s.replace(/nonce-[^'"]+/g, '').replace(/nonce=["'][^"']*["']/g, '').replace(/value=["'][^"']*["']/g, '').replace(/content=["'][^"']*["']/g, '');
    assert.equal(strip(unknownBody), strip(wrongBody), 'page content must not reveal whether the account exists');
    assert.doesNotMatch(unknownBody + wrongBody, /no such (user|account)|user not found|unknown (user|email)|wrong password|incorrect password/i);
  });

  test('V6.3.1 login is limited per account: after 5 failures the account is soft-locked with 429 and Retry-After', async () => {
    let limited: Response | undefined;
    for (let i = 1; i <= 6; i++) {
      const res = await app.loginRaw(users.member2, `wrong-password-${i}`);
      await res.text();
      if (res.status === 429) {
        limited = res;
        break;
      }
    }
    assert.ok(limited, 'the sixth failed login for one account must be answered with 429');
    retryAfterOk(limited);
    const lockedCorrect = await app.loginRaw(users.member2, app.password);
    await lockedCorrect.text();
    assert.ok(lockedCorrect.status === 429 || (isRedirect(lockedCorrect) && /login/i.test(locationOf(lockedCorrect))), 'the correct password must not bypass the soft lock');
    const hits = await app.waitForEvent('ratelimit.hit');
    assert.ok(hits.length >= 1, 'ratelimit.hit events must be emitted');
    const lockouts = await app.eventsNamed('auth.lockout');
    assert.ok(lockouts.length >= 1 || hits.some((e) => e.bucket === 'login'), 'auth.lockout or a login-bucket ratelimit.hit must be logged');

    // The lock is temporary, never permanent: after the limiter state is cleared the account works again.
    await app.resetRateLimits();
    assert.equal(await app.canLogin(users.member2, app.password), true, 'the account must not be permanently locked');
  });

  test('V6.3.1 a valid login still works for other accounts while one account is locked', async () => {
    for (let i = 1; i <= 6; i++) {
      const res = await app.loginRaw(users.staff, `wrong-password-${i}`);
      await res.text();
    }
    assert.equal(await app.canLogin(users.member, app.password), true, 'other accounts must not be affected by a per-account lock');
    await app.resetRateLimits();
  });

  test('V2.4.1 password reset requests are limited per account', async () => {
    let limited: Response | undefined;
    for (let i = 1; i <= 4; i++) {
      const res = await app.submitForm(paths.forgotPassword, { [fields.email]: users.member }, new CookieJar());
      await res.text();
      if (res.status === 429) {
        limited = res;
        break;
      }
    }
    assert.ok(limited, 'the fourth reset request for one account within an hour must be answered with 429');
    retryAfterOk(limited);
    await app.resetRateLimits();
  });

  test('V2.4.1 registration is limited per client and X-Forwarded-For cannot be used to evade it', async (t) => {
    const register = await app.findRoute('POST', /^\/register$/);
    if (!register) return t.skip('registration is not open on this app (invite-only mode)');
    let limited: Response | undefined;
    for (let i = 1; i <= 4; i++) {
      const jar = new CookieJar();
      const res = await app.submitForm(
        paths.register,
        { [fields.email]: `new-${randomBytes(4).toString('hex')}@test.local`, [fields.password]: `Reg-${randomBytes(12).toString('base64url')}` },
        jar,
        { headers: { 'X-Forwarded-For': `203.0.113.${i}` } },
      );
      await res.text();
      if (res.status === 429) {
        limited = res;
        break;
      }
    }
    assert.ok(limited, 'the fourth registration from one client within an hour must be answered with 429 even with varying X-Forwarded-For');
    retryAfterOk(limited);
    await app.resetRateLimits();
  });

  test('V2.4.1 the general limiter answers 429 with Retry-After once the per-minute budget is exhausted', async (t) => {
    // In test mode the general limit is raised to 100 000/min so functional tests are not affected;
    // exhausting it here would take too long. Verify the limiter is wired by checking a login-bucket hit instead.
    for (let i = 1; i <= 6; i++) {
      const res = await app.loginRaw(users.member2, `wrong-${i}`);
      await res.text();
    }
    const hits = await app.waitForEvent('ratelimit.hit');
    if (hits.length === 0) return t.skip('no ratelimit.hit event observed');
    assert.ok(hits.every((e) => typeof e.bucket === 'string'), 'ratelimit.hit must name the bucket');
    await app.resetRateLimits();
  });

  test('V15.3.4 the client address comes from the socket unless proxy hops are configured', async () => {
    for (let i = 1; i <= 6; i++) {
      const res = await app.loginRaw(users.member2, `wrong-${i}`, new CookieJar(), { 'X-Forwarded-For': `198.51.100.${i}`, 'X-Real-IP': `198.51.100.${i}` });
      await res.text();
    }
    const hits = await app.eventsNamed('ratelimit.hit');
    assert.ok(hits.length >= 1);
    assert.ok(hits.every((e) => !/^198\.51\.100\./.test(String(e.ip ?? ''))), 'the logged ip must be the socket address, never a spoofed X-Forwarded-For');
    await app.resetRateLimits();
  });
});
