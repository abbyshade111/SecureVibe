/**
 * Log-evidence probes: cause a security-relevant event, then check /__securevibe/events recorded it.
 */
import { CookieJar, extractCsrfToken } from '../http.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule, type SecurityEvent } from '../types.js';
import { fail, pass, nowIso, sleep } from './util.js';

async function eventsAfter(ctx: ProbeContext, since: string, name: string): Promise<SecurityEvent | undefined> {
  for (let attempt = 0; attempt < 3; attempt++) {
    const events = await ctx.events(since);
    const hit = events.find((e) => e.event === name);
    if (hit) return hit;
    await sleep(150);
  }
  return undefined;
}

export const logLoginFailureLogged: ProbeModule = {
  id: 'dast.log.login-failure-logged',
  group: 'log',
  requirementIds: ['V16.3.1', 'V16.2.1'],
  fallback: {
    title: 'Failed sign-ins are not logged',
    severity: 'medium',
    cwe: ['CWE-778'],
    description: 'A wrong-password sign-in produced no auth.login.failure security event.',
    impact: 'Password-guessing attacks go unnoticed and cannot be investigated afterwards.',
    fix: 'Emit auth.login.failure with the reason and a hashed email on every failed sign-in.',
  },
  async run(ctx) {
    const user = ctx.seededUsers.find((u) => u.label === 'member2') ?? ctx.seededUsers[0];
    if (!user) return NOT_ATTEMPTED('no seeded user');
    const expected = 'a wrong password produces an auth.login.failure event';
    const since = nowIso();
    const res = await ctx.loginAttempt(user.email, 'wrong-password-for-the-log-probe');
    const hit = await eventsAfter(ctx, since, 'auth.login.failure');
    return hit ? pass(expected, `auth.login.failure recorded (outcome ${String(hit.outcome ?? '')})`, res) : fail(expected, `sign-in answered ${res.status} but no auth.login.failure event appeared`, res);
  },
};

export const logAuthzDenialLogged: ProbeModule = {
  id: 'dast.log.authz-denial-logged',
  group: 'log',
  requirementIds: ['V16.3.2', 'V16.3.1'],
  fallback: {
    title: 'Permission denials are not logged',
    severity: 'medium',
    cwe: ['CWE-778'],
    description: 'A signed-in user hitting an admin route produced no authz.denied security event.',
    impact: 'Attempts to reach other people’s data are invisible.',
    fix: 'Call forbid() (which emits authz.denied) for every authorization failure.',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member') ?? ctx.sessions.get('member2');
    const admin = ctx.paths.adminPage;
    if (!session || !admin) return NOT_ATTEMPTED(session ? 'no admin-only route is registered' : 'no signed-in non-admin session');
    const expected = `a member requesting ${admin} produces an authz.denied event`;
    const since = nowIso();
    const res = await ctx.http.get(admin, { jar: session.jar });
    const hit = await eventsAfter(ctx, since, 'authz.denied');
    return hit ? pass(expected, `authz.denied recorded (status ${res.status})`, res) : fail(expected, `${admin} answered ${res.status} but no authz.denied event appeared`, res);
  },
};

export const logValidationRejectedLogged: ProbeModule = {
  id: 'dast.log.validation-rejected-logged',
  group: 'log',
  requirementIds: ['V16.3.3'],
  fallback: {
    title: 'Rejected input is not logged',
    severity: 'low',
    cwe: ['CWE-778'],
    description: 'A request with an unknown field produced no validation.rejected security event.',
    impact: 'Probing for weaknesses (unexpected fields, malformed values) leaves no trace.',
    fix: 'Emit validation.rejected with the route and field on every schema failure.',
  },
  async run(ctx) {
    const expected = 'a sign-in form with an unknown field produces a validation.rejected event';
    const since = nowIso();
    const jar = new CookieJar();
    const page = await ctx.http.get(ctx.paths.login, { jar });
    const token = extractCsrfToken(page.body);
    const res = await ctx.http.form(ctx.paths.login, { _csrf: token ?? '', email: 'probe@test.local', password: 'not-the-password-123456', unexpectedField: '1' }, { jar });
    const hit = await eventsAfter(ctx, since, 'validation.rejected');
    return hit ? pass(expected, `validation.rejected recorded (status ${res.status})`, res) : fail(expected, `sign-in answered ${res.status} but no validation.rejected event appeared`, res);
  },
};

export const logProbes: ProbeModule[] = [logLoginFailureLogged, logAuthzDenialLogged, logValidationRejectedLogged];
