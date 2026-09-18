/**
 * Cross-site scripting smoke tests: a reflected payload in the sign-in form and query, and a stored payload
 * created through the JSON API and read back as the same user.
 */
import { CookieJar, extractCsrfToken } from '../http.js';
import { NOT_ATTEMPTED, type ProbeModule } from '../types.js';
import { fail, findRoute, jsonCreateRoute, pass, sampleFromSchema } from './util.js';

const PAYLOAD = `svp"><img src=x onerror=alert('svp')><script>svp()</script>`;
const RAW_MARKERS = [`<img src=x onerror=alert('svp')>`, '<script>svp()</script>'];

function unescaped(html: string): boolean {
  return RAW_MARKERS.some((m) => html.includes(m));
}

export const xssReflectedSmoke: ProbeModule = {
  id: 'dast.xss.reflected-smoke',
  group: 'xss',
  requirementIds: ['V1.2.1', 'V3.2.2'],
  fallback: {
    title: 'Reflected input is not escaped',
    severity: 'high',
    cwe: ['CWE-79'],
    description: 'Text sent to the app came back in a page without HTML escaping.',
    impact: 'A crafted link runs script in the victim’s browser with their session.',
    fix: 'Output data only with <%= %> in EJS and never build HTML from user input.',
  },
  async run(ctx) {
    const expected = 'a script payload sent in the sign-in email field and in the query string never comes back unescaped';
    const jar = new CookieJar();
    const page = await ctx.http.get(ctx.paths.login, { jar });
    const token = extractCsrfToken(page.body);
    const form = await ctx.http.form(ctx.paths.login, { _csrf: token ?? '', email: `${PAYLOAD}@test.local`, password: 'not-the-password-123456' }, { jar });
    if (unescaped(form.body)) return fail(expected, `the payload came back unescaped from POST ${ctx.paths.login} (status ${form.status})`, form);
    const query = await ctx.http.get(`${ctx.paths.login}?next=${encodeURIComponent(PAYLOAD)}`);
    if (unescaped(query.body)) return fail(expected, 'the payload came back unescaped from the query string', query);
    const notFound = await ctx.http.get(`/${encodeURIComponent(PAYLOAD)}`);
    if (unescaped(notFound.body)) return fail(expected, 'the payload came back unescaped in the 404 page', notFound);
    return pass(expected, 'no unescaped reflection in the form, query or 404 responses', form);
  },
};

export const xssStoredSmoke: ProbeModule = {
  id: 'dast.xss.stored-smoke',
  group: 'xss',
  requirementIds: ['V1.2.1', 'V3.2.2'],
  fallback: {
    title: 'Stored input is not escaped',
    severity: 'high',
    cwe: ['CWE-79'],
    description: 'A record created with a script payload was rendered unescaped when read back.',
    impact: 'One user’s stored text runs script in every other user’s browser that views it.',
    fix: 'Render stored fields with EJS escaping and never mark user text as safe HTML.',
  },
  async run(ctx) {
    const target = jsonCreateRoute(ctx);
    const session = ctx.sessions.get('member');
    if (!target || !session) return NOT_ATTEMPTED(target ? 'the member account could not sign in' : 'no JSON create route is registered');
    const expected = `a record created via ${target.route.path} with a script payload is escaped wherever it is rendered as HTML`;
    const csrf = await ctx.csrf(session);
    // With a body schema only free-text fields carry the payload, so choices, dates and e-mail addresses stay valid.
    const fromSchema = sampleFromSchema(target.route.bodySchema, `${PAYLOAD} Runtime check`);
    const body: Record<string, unknown> = {};
    if (fromSchema && typeof fromSchema === 'object') Object.assign(body, fromSchema);
    else for (const [k, v] of Object.entries(target.body)) body[k] = typeof v === 'string' ? `${PAYLOAD} ${v}` : v;
    const created = await ctx.http.json(target.route.path, body, { jar: session.jar, csrfToken: csrf });
    if (created.status >= 400) return NOT_ATTEMPTED(`creating a record answered ${created.status}`, expected);
    const id = (created.json<{ id?: string; note?: { id?: string }; data?: { id?: string } }>() ?? {});
    const recordId = id.id ?? id.note?.id ?? id.data?.id;
    const checks = [] as { path: string; html: boolean }[];
    if (recordId) {
      const getRoute = findRoute(ctx, (r) => r.method === 'GET' && r.path.startsWith(target.route.path) && /:[A-Za-z0-9_]+/.test(r.path));
      if (getRoute) checks.push({ path: getRoute.path.replace(/:[A-Za-z0-9_]+\??/, recordId), html: false });
    }
    checks.push({ path: target.route.path, html: false });
    const entity = target.route.entity ?? target.route.path.split('/').filter(Boolean).pop() ?? '';
    const pageRoute = findRoute(ctx, (r) => r.method === 'GET' && (r.kind ?? 'page') === 'page' && !/:[A-Za-z0-9_]+/.test(r.path) && r.auth !== 'public' && new RegExp(entity, 'i').test(r.path));
    if (pageRoute) checks.push({ path: pageRoute.path, html: true });
    let sawHtml = false;
    let last;
    for (const check of checks) {
      const res = await ctx.http.get(check.path, { jar: session.jar, headers: { Accept: check.html ? 'text/html' : 'application/json' } });
      last = res;
      if (/text\/html/.test(res.contentType())) {
        sawHtml = true;
        if (unescaped(res.body)) return fail(expected, `the payload is rendered unescaped on ${check.path}`, res);
      } else if (/application\/json/.test(res.contentType()) && !/nosniff/i.test(res.header('x-content-type-options') ?? '')) {
        return fail(expected, `${check.path} returns JSON without nosniff`, res);
      }
    }
    return pass(expected, sawHtml ? 'stored payload is escaped on the HTML page and returned as data by the API' : 'no HTML page renders this record; the API returns it as JSON data with nosniff', last);
  },
};

export const xssProbes: ProbeModule[] = [xssReflectedSmoke, xssStoredSmoke];
