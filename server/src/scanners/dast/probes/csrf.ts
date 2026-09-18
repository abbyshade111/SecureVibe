/**
 * Cross-site request forgery probes: a missing token is refused, a foreign Origin is refused even with a valid
 * token, and GET never changes state.
 */
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule, type Session } from '../types.js';
import { fail, hasParams, isTestEndpoint, pass, routesOf } from './util.js';

async function stillSignedIn(ctx: ProbeContext, session: Session): Promise<boolean> {
  const res = await ctx.http.get(ctx.pageFor('user') ?? ctx.paths.account, { jar: session.jar });
  return res.status === 200;
}

export const csrfMissingTokenRejected: ProbeModule = {
  id: 'dast.csrf.missing-token-rejected',
  group: 'csrf',
  requirementIds: ['V3.5.1', 'V3.5.3'],
  fallback: {
    title: 'State-changing request accepted without a CSRF token',
    severity: 'high',
    cwe: ['CWE-352'],
    description: 'A POST without the synchronizer token was processed instead of being refused with 403.',
    impact: 'Another website could make a signed-in user perform actions without their knowledge.',
    fix: 'Keep csrfProtect on every state-changing route (the registry adds it by default).',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member2') ?? ctx.sessions.get('member');
    if (!session) return NOT_ATTEMPTED('no signed-in session was available');
    const expected = `POST ${ctx.paths.logout} without _csrf answers 403 and the session stays signed in`;
    const res = await ctx.http.form(ctx.paths.logout, {}, { jar: session.jar });
    if (res.status !== 403) return fail(expected, `status ${res.status}`, res);
    if (!(await stillSignedIn(ctx, session))) return fail(expected, 'answered 403 but the session was ended anyway', res);
    return pass(expected, '403 and the session is still valid', res);
  },
};

export const csrfCrossOriginRejected: ProbeModule = {
  id: 'dast.csrf.cross-origin-rejected',
  group: 'csrf',
  requirementIds: ['V3.5.1', 'V3.5.3'],
  fallback: {
    title: 'Cross-origin request accepted',
    severity: 'high',
    cwe: ['CWE-352'],
    description: 'A POST with a valid token but a foreign Origin (or Sec-Fetch-Site: cross-site) was processed.',
    impact: 'The Origin check is the second line of defence when a token leaks; without it one leak is enough.',
    fix: 'Refuse state-changing requests whose Origin is not this site or whose Sec-Fetch-Site is cross-site.',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member2') ?? ctx.sessions.get('member');
    if (!session) return NOT_ATTEMPTED('no signed-in session was available');
    const expected = `POST ${ctx.paths.logout} with a valid token but Origin: https://evil.example (or Sec-Fetch-Site: cross-site) answers 403`;
    const token = await ctx.csrf(session);
    if (!token) return NOT_ATTEMPTED('no CSRF token could be read from a signed-in page', expected);
    const foreign = await ctx.http.form(ctx.paths.logout, { _csrf: token }, { jar: session.jar, headers: { Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' } });
    if (foreign.status !== 403) return fail(expected, `foreign Origin answered ${foreign.status}`, foreign);
    const fetchSite = await ctx.http.form(ctx.paths.logout, { _csrf: token }, { jar: session.jar, headers: { Origin: ctx.http.origin, 'Sec-Fetch-Site': 'cross-site' } });
    if (fetchSite.status !== 403) return fail(expected, `Sec-Fetch-Site: cross-site answered ${fetchSite.status}`, fetchSite);
    if (!(await stillSignedIn(ctx, session))) return fail(expected, 'answered 403 but the session was ended anyway', foreign);
    return pass(expected, 'both refused with 403; session intact', foreign);
  },
};

const MUTATING_WORDS = /\b(delete|remove|revoke|disable|enable|logout|reset|toggle|approve|confirm|cancel|destroy)\b/i;

export const csrfGetDoesNotMutate: ProbeModule = {
  id: 'dast.csrf.get-does-not-mutate',
  group: 'csrf',
  requirementIds: ['V3.5.1'],
  fallback: {
    title: 'GET requests can change state',
    severity: 'high',
    cwe: ['CWE-352', 'CWE-650'],
    description: 'A GET route performs an action (for example GET /logout works, or a GET route is named like an action).',
    impact: 'A link or image tag on any website can trigger the action for a signed-in user.',
    fix: 'Make every state change a POST/PUT/PATCH/DELETE with CSRF protection; GET only reads.',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member2') ?? ctx.sessions.get('member');
    const expected = 'GET /logout does not sign out (405/404) and no GET route is named like an action';
    const routes = routesOf(ctx);
    // "GET shows the form, POST does the work" at the same address is the safe pattern (a confirmation page).
    const hasStateChangingTwin = (path: string) => routes.some((r) => r.method !== 'GET' && r.path === path);
    const named = routes.filter(
      (r) => r.method === 'GET' && !isTestEndpoint(r.path) && MUTATING_WORDS.test(r.path.split('?')[0] ?? '') && !hasStateChangingTwin(r.path),
    );
    if (named.length > 0) {
      return fail(expected, `GET routes named like actions: ${named.map((r) => r.path).join(', ')}`, undefined, {
        failures: named.map((r) => ({ endpoint: `GET ${r.path}`, observed: 'a GET route whose path names a state change' })),
      });
    }
    if (!session) return NOT_ATTEMPTED('no signed-in session was available', expected);
    const res = await ctx.http.get(ctx.paths.logout, { jar: session.jar });
    if (res.status === 200 || res.isRedirect()) {
      if (!(await stillSignedIn(ctx, session))) return fail(expected, `GET ${ctx.paths.logout} signed the user out (status ${res.status})`, res);
    }
    return pass(expected, `GET ${ctx.paths.logout} answered ${res.status}; session intact; no action-named GET routes`, res);
  },
};

/** Routes with parameters are checked by the authz probes; this list keeps the CSRF family self-contained. */
export function csrfProtectedRoutes(ctx: ProbeContext): number {
  return routesOf(ctx).filter((r) => r.csrf && !hasParams(r)).length;
}

export const csrfProbes: ProbeModule[] = [csrfMissingTokenRejected, csrfCrossOriginRejected, csrfGetDoesNotMutate];
