/**
 * Open-redirect probe: the sign-in `next` parameter must never send the browser to another site.
 */
import { CookieJar, extractCsrfToken } from '../http.js';
import type { ProbeModule } from '../types.js';
import { fail, pass } from './util.js';

const OFFSITE = ['https://evil.example/', '//evil.example/', '/\\evil.example', 'https:evil.example', '%2F%2Fevil.example'];

function goesOffsite(location: string, origin: string): boolean {
  if (!location) return false;
  if (/^https?:\/\//i.test(location)) return !location.startsWith(origin);
  return /^[/\\]{2}|evil\.example/i.test(location);
}

export const redirectOpenRedirectBlocked: ProbeModule = {
  id: 'dast.redirect.open-redirect-blocked',
  group: 'redirect',
  requirementIds: ['V3.7.2', 'V1.2.2'],
  fallback: {
    title: 'Open redirect through the next parameter',
    severity: 'medium',
    cwe: ['CWE-601'],
    description: 'A `next` value pointing to another site was accepted and produced a redirect off the app.',
    impact: 'Phishing links can bounce through the trusted app to a fake sign-in page.',
    fix: 'Accept only local paths (starting with a single /) for next and use safeRedirect with an allow-list.',
  },
  async run(ctx) {
    const user = ctx.seededUsers.find((u) => u.label === 'member2' && !u.mfa) ?? ctx.seededUsers.find((u) => !u.mfa);
    const expected = 'off-site next values are refused (400) or ignored; no redirect ever leaves the app';
    let last;
    for (const target of OFFSITE) {
      const page = await ctx.http.get(`${ctx.paths.login}?next=${encodeURIComponent(target)}`);
      last = page;
      if (page.isRedirect() && goesOffsite(page.location(), ctx.http.origin)) return fail(expected, `GET /login?next=${target} redirected to ${page.location()}`, page);
      if (!user) continue;
      const jar = new CookieJar();
      const form = await ctx.http.get(ctx.paths.login, { jar });
      const token = extractCsrfToken(form.body);
      const res = await ctx.http.form(ctx.paths.login, { _csrf: token ?? '', email: user.email, password: ctx.secrets.password, next: target }, { jar });
      last = res;
      if (res.isRedirect() && goesOffsite(res.location(), ctx.http.origin)) return fail(expected, `sign-in with next=${target} redirected to ${res.location()}`, res);
      if (res.isRedirect()) {
        const token2 = extractCsrfToken((await ctx.http.get(ctx.paths.account, { jar })).body);
        await ctx.http.form(ctx.paths.logout, { ...(token2 ? { _csrf: token2 } : {}) }, { jar });
      }
    }
    return pass(expected, `${OFFSITE.length} off-site targets never produced an off-site redirect`, last);
  },
};

export const redirectProbes: ProbeModule[] = [redirectOpenRedirectBlocked];
