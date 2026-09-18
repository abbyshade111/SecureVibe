/**
 * Session probes: Clear-Site-Data on logout, session id never in URLs, id format and randomness, rotation on
 * sign-in, no reuse after logout, and a visible logout control on signed-in pages.
 */
import { CookieJar, extractCsrfToken, isSessionSetCookie, parseSetCookie } from '../http.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule } from '../types.js';
import { fail, pass } from './util.js';

/** Signs out like the app's own page would: the CSRF token as a form field and as the X-CSRF-Token header. */
async function logoutWith(ctx: ProbeContext, jar: CookieJar, knownToken?: string): Promise<import('../http.js').HttpResponse> {
  const page = await ctx.http.get(ctx.pageFor('user') ?? ctx.paths.account, { jar });
  const token = extractCsrfToken(page.body) ?? knownToken;
  return ctx.http.form(ctx.paths.logout, { ...(token ? { _csrf: token } : {}) }, { jar, ...(token ? { headers: { 'X-CSRF-Token': token } } : {}) });
}

export const sessionLogoutClearSiteData: ProbeModule = {
  id: 'dast.session.logout-clear-site-data',
  group: 'session',
  requirementIds: ['V14.3.1'],
  fallback: {
    title: 'Logout does not clear browser data',
    severity: 'low',
    cwe: ['CWE-613'],
    description: 'The logout response did not carry Clear-Site-Data: "cookies", "storage".',
    impact: 'Leftover cookies or storage may let the next person on a shared computer continue where the user left off.',
    fix: 'Send Clear-Site-Data: "cookies", "storage" on the logout response.',
  },
  async run(ctx) {
    const session = await ctx.login('member2');
    if (!session) return NOT_ATTEMPTED('could not sign in a throw-away session');
    const expected = 'POST /logout answers with Clear-Site-Data including "cookies"';
    const res = await logoutWith(ctx, session.jar, session.csrfToken);
    const header = res.header('clear-site-data') ?? '';
    if (!/"cookies"/.test(header)) return fail(expected, `Clear-Site-Data: ${header || 'missing'} (status ${res.status})`, res);
    return pass(expected, `Clear-Site-Data: ${header}`, res);
  },
};

export const sessionCookieNotInUrl: ProbeModule = {
  id: 'dast.session.cookie-not-in-url',
  group: 'session',
  requirementIds: ['V3.3.4', 'V14.2.1'],
  fallback: {
    title: 'Session id appears in a URL',
    severity: 'high',
    cwe: ['CWE-598'],
    description: 'The session id was found in a redirect location or a link on a signed-in page.',
    impact: 'Session ids in URLs leak through logs, history and the Referer header.',
    fix: 'Keep the session id only in the HttpOnly cookie; never put it in query strings or links.',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member') ?? ctx.sessions.get('staff');
    if (!session) return NOT_ATTEMPTED('no signed-in session was available');
    const expected = 'the session id never appears in redirect locations, links or page bodies';
    const id = session.jar.sessionId();
    if (!id) return NOT_ATTEMPTED('the signed-in jar has no session cookie', expected);
    const page = await ctx.http.get(ctx.pageFor('user') ?? ctx.paths.account, { jar: session.jar });
    const home = await ctx.http.get('/', { jar: session.jar });
    for (const res of [page, home]) {
      if (res.body.includes(id) || res.location().includes(id)) return fail(expected, `the session id appears in the response for ${res.request.path}`, res);
      if (/[?&](sid|session|sessionid|token)=/i.test(res.location())) return fail(expected, `a redirect carries a session-like parameter: ${res.location()}`, res);
    }
    return pass(expected, 'session id only in the cookie', page);
  },
};

export const sessionIdFormat: ProbeModule = {
  id: 'dast.session.id-format',
  group: 'session',
  requirementIds: ['V7.2.1', 'V7.2.2'],
  fallback: {
    title: 'Session id too short or predictable',
    severity: 'high',
    cwe: ['CWE-330', 'CWE-331'],
    description: 'The session cookie value is shorter than 32 random bytes (base64url, at least 43 characters) or two fresh sessions share a prefix.',
    impact: 'Short or sequential ids can be guessed, letting an attacker take over sessions.',
    fix: 'Generate session ids with 32 bytes from crypto.randomBytes encoded as base64url.',
  },
  async run(ctx) {
    const expected = 'session ids are base64url strings of at least 43 characters and differ between sessions';
    const jars = [new CookieJar(), new CookieJar()];
    let last;
    for (const jar of jars) last = await ctx.http.get(ctx.paths.login, { jar });
    const ids = jars.map((j) => j.sessionId()).filter((v): v is string => Boolean(v));
    if (ids.length < 2) {
      const attempt = await ctx.loginAttempt('nobody@test.local', 'not-the-password-123456', jars[0]);
      const attempt2 = await ctx.loginAttempt('nobody@test.local', 'not-the-password-123456', jars[1]);
      last = attempt2;
      ids.length = 0;
      for (const j of jars) if (j.sessionId()) ids.push(j.sessionId()!);
      // Apps that only issue a session on a successful sign-in: sign in twice with the right credentials.
      const seeded = ctx.seededUsers[0];
      if (ids.length < 2 && seeded && ctx.secrets.password) {
        const fresh = [new CookieJar(), new CookieJar()];
        for (const jar of fresh) last = await ctx.loginAttempt(seeded.email, ctx.secrets.password, jar);
        ids.length = 0;
        for (const j of fresh) if (j.sessionId()) ids.push(j.sessionId()!);
      }
      if (ids.length < 2) return NOT_ATTEMPTED(`no session cookie observed (status ${attempt.status})`, expected);
    }
    for (const id of ids) {
      if (!/^[A-Za-z0-9_-]+$/.test(id)) return fail(expected, `id contains characters outside base64url: ${id.slice(0, 8)}…`, last);
      if (id.length < 43) return fail(expected, `id is only ${id.length} characters`, last);
    }
    if (ids[0] === ids[1] || ids[0]!.slice(0, 8) === ids[1]!.slice(0, 8)) return fail(expected, 'two fresh sessions share the same prefix', last);
    return pass(expected, `ids are ${ids[0]!.length} characters of base64url and differ`, last);
  },
};

export const sessionRotatedOnLogin: ProbeModule = {
  id: 'dast.session.rotated-on-login',
  group: 'session',
  requirementIds: ['V7.2.4'],
  fallback: {
    title: 'Session id not renewed on sign-in',
    severity: 'high',
    cwe: ['CWE-384'],
    description: 'The session id before and after a successful sign-in was the same, or the old id still worked.',
    impact: 'Session fixation: an attacker who plants a session id before sign-in inherits the signed-in session.',
    fix: 'Regenerate the session id on sign-in (and on the one-time code step) and revoke the old one.',
  },
  async run(ctx) {
    const user = ctx.seededUsers.find((u) => u.label === 'member2' && !u.mfa) ?? ctx.seededUsers.find((u) => !u.mfa);
    if (!user) return NOT_ATTEMPTED('no seeded user without a second factor');
    const expected = 'the session id changes on sign-in and the pre-login id is no longer signed in';
    const jar = new CookieJar();
    await ctx.http.get(ctx.paths.login, { jar });
    const before = jar.sessionId();
    const res = await ctx.loginAttempt(user.email, ctx.secrets.password, jar);
    if (!res.isRedirect()) return NOT_ATTEMPTED(`sign-in answered ${res.status}`, expected);
    const setLine = res.setCookies.find((c) => isSessionSetCookie(c));
    const after = setLine ? parseSetCookie(setLine).value : jar.sessionId();
    if (!after) return fail(expected, 'no session cookie was set on sign-in', res);
    if (before && before === after) return fail(expected, 'the same session id was kept across sign-in', res);
    if (before) {
      const old = new CookieJar();
      old.cookies.set(jar.sessionCookieName() ?? 'sid', before);
      const check = await ctx.http.get(ctx.pageFor('user') ?? ctx.paths.account, { jar: old });
      if (check.status === 200) return fail(expected, 'the pre-login session id is signed in too', check);
    }
    await logoutWith(ctx, jar);
    return pass(expected, before ? 'new id issued; old id is anonymous' : 'a fresh id was issued on sign-in (no pre-login session existed)', res);
  },
};

export const sessionReuseAfterLogoutDenied: ProbeModule = {
  id: 'dast.session.reuse-after-logout-denied',
  group: 'session',
  requirementIds: ['V7.4.1'],
  fallback: {
    title: 'Session still valid after logout',
    severity: 'high',
    cwe: ['CWE-613'],
    description: 'After signing out, the old session cookie still opened a signed-in page.',
    impact: 'A copied cookie keeps working after the user believes they signed out.',
    fix: 'Revoke the session row on logout, not just the cookie.',
  },
  async run(ctx) {
    const session = await ctx.login('member2');
    if (!session) return NOT_ATTEMPTED('could not sign in a throw-away session');
    const expected = 'after POST /logout the old cookie no longer opens a signed-in page';
    const page = ctx.pageFor('user') ?? ctx.paths.account;
    const copy = session.jar.clone();
    const before = await ctx.http.get(page, { jar: copy });
    if (before.status !== 200) return NOT_ATTEMPTED(`${page} answered ${before.status} for a fresh session`, expected);
    const logout = await logoutWith(ctx, session.jar, session.csrfToken);
    if (logout.status >= 400) return NOT_ATTEMPTED(`logout answered ${logout.status}`, expected);
    const after = await ctx.http.get(page, { jar: copy });
    if (after.status === 200) return fail(expected, 'the old cookie still opens the page after logout', after);
    return pass(expected, `after logout the page answers ${after.status}`, after);
  },
};

export const sessionLogoutVisible: ProbeModule = {
  id: 'dast.session.logout-visible',
  group: 'session',
  requirementIds: ['V7.4.4'],
  fallback: {
    title: 'No logout control on signed-in pages',
    severity: 'low',
    cwe: ['CWE-613'],
    description: 'A signed-in page has no form or button that posts to the logout route.',
    impact: 'Users on shared computers cannot end their session easily.',
    fix: 'Render the logout form in the base layout for every authenticated page.',
  },
  async run(ctx) {
    const session = ctx.sessions.get('member') ?? ctx.sessions.get('staff') ?? ctx.sessions.get('admin');
    if (!session) return NOT_ATTEMPTED('no signed-in session was available');
    const expected = `signed-in pages contain a form posting to ${ctx.paths.logout}`;
    const pages = [ctx.pageFor('user') ?? ctx.paths.account, '/'];
    let last;
    for (const p of pages) {
      const res = await ctx.http.get(p, { jar: session.jar });
      last = res;
      if (res.status !== 200) continue;
      const re = new RegExp(`<form[^>]+action=["']${ctx.paths.logout.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}["']`, 'i');
      if (re.test(res.body) && /method=["']post["']/i.test(res.body)) return pass(expected, `logout form found on ${p}`, res);
    }
    return fail(expected, 'no logout form found on the signed-in pages checked', last);
  },
};

export const sessionProbes: ProbeModule[] = [
  sessionIdFormat,
  sessionCookieNotInUrl,
  sessionRotatedOnLogin,
  sessionLogoutVisible,
  sessionLogoutClearSiteData,
  sessionReuseAfterLogoutDenied,
];
