/**
 * Input-handling probes: body limits, parameter pollution, prototype pollution, unknown fields, type confusion,
 * injection smoke tests, path traversal, JSON API content type, idempotency keys and API-key placement.
 */
import { CookieJar, extractCsrfToken, formBody, type HttpResponse } from '../http.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeFailure, type ProbeModule, type RouteInfo } from '../types.js';
import { bodyGuess, fail, failureFrom, fillPath, hasParams, isTestEndpoint, jsonCreateRoute, leaksTechnicalDetail, pass, routesOf, summarize } from './util.js';

async function loginCsrf(ctx: ProbeContext): Promise<{ token: string | undefined; jar: CookieJar }> {
  const jar = new CookieJar();
  const page = await ctx.http.get(ctx.paths.login, { jar });
  return { token: extractCsrfToken(page.body), jar };
}

function rejected(status: number): boolean {
  return status === 400 || status === 413 || status === 415 || status === 422;
}

export const inputOversizedBody: ProbeModule = {
  id: 'dast.input.oversized-body',
  group: 'input',
  requirementIds: ['V15.3.6', 'V2.4.1'],
  fallback: {
    title: 'Oversized request bodies are accepted',
    severity: 'medium',
    cwe: ['CWE-400'],
    description: 'A request body far above the configured limit was not refused with 413.',
    impact: 'Large bodies let one client exhaust memory and make the app unavailable.',
    fix: 'Keep the JSON and form body limits (100kb) in src/app.ts.',
  },
  async run(ctx) {
    const expected = 'a 300 KB form body to POST /login is refused with 413 (or 400)';
    const { token, jar } = await loginCsrf(ctx);
    const padding = 'x'.repeat(300 * 1024);
    const res = await ctx.http.form(ctx.paths.login, { _csrf: token ?? '', email: 'probe@test.local', password: padding }, { jar });
    if (res.status === 413 || res.status === 400) return pass(expected, `status ${res.status}`, res);
    return fail(expected, `status ${res.status}`, res);
  },
};

export const inputDuplicateParam: ProbeModule = {
  id: 'dast.input.duplicate-param',
  group: 'input',
  requirementIds: ['V15.3.7', 'V2.2.2'],
  fallback: {
    title: 'Repeated parameters are not rejected',
    severity: 'medium',
    cwe: ['CWE-235'],
    description: 'Sending the same query or form parameter twice was accepted instead of answering 400.',
    impact: 'Parameter pollution can bypass validation or change which value a check and a use see.',
    fix: 'Keep the simple query parser and strict schemas that reject arrays where a single value is expected.',
  },
  async run(ctx) {
    const expected = `${ctx.paths.login}?next=/a&next=/b answers 400 and a form with two email fields answers 400`;
    const query = await ctx.http.get(`${ctx.paths.login}?next=%2Fa&next=%2Fb`);
    if (query.status !== 400) return fail(expected, `duplicate query parameter answered ${query.status}`, query);
    const { token, jar } = await loginCsrf(ctx);
    const body = `${formBody({ _csrf: token ?? '' })}&email=a%40test.local&email=b%40test.local&password=not-a-real-password-1`;
    const form = await ctx.http.request(ctx.paths.login, { method: 'POST', jar, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body });
    if (form.status !== 400) return fail(expected, `duplicate form field answered ${form.status}`, form);
    return pass(expected, 'both answered 400', form);
  },
};

export const inputProtoPollution: ProbeModule = {
  id: 'dast.input.proto-pollution',
  group: 'input',
  requirementIds: ['V15.3.6', 'V1.2.5'],
  fallback: {
    title: 'Prototype-pollution keys are accepted',
    severity: 'high',
    cwe: ['CWE-1321'],
    description: 'A request containing __proto__ / constructor / prototype keys was not refused with 400.',
    impact: 'Prototype pollution can change how every object in the app behaves, up to running attacker code.',
    fix: 'Keep the rejectPrototypePollution middleware that answers 400 for these keys in bodies and queries.',
  },
  async run(ctx) {
    const expected = 'bodies and queries with __proto__ / constructor keys answer 400, never 500';
    const { token, jar } = await loginCsrf(ctx);
    const checks: HttpResponse[] = [];
    checks.push(await ctx.http.get(`${ctx.paths.login}?__proto__[polluted]=1`));
    checks.push(await ctx.http.request(ctx.paths.login, { method: 'POST', jar, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${formBody({ _csrf: token ?? '' })}&__proto__[polluted]=1&email=a%40test.local&password=not-a-real-password-1` }));
    const target = jsonCreateRoute(ctx);
    const session = ctx.sessions.get('member');
    if (target && session) {
      const csrf = await ctx.csrf(session);
      // Built as text: an object literal with __proto__ would set the prototype and JSON.stringify would drop it.
      const rest = JSON.stringify(target.body).slice(1);
      checks.push(await ctx.http.json(target.route.path, undefined, { jar: session.jar, csrfToken: csrf, raw: `{"__proto__":{"polluted":true},${rest}` }));
      checks.push(await ctx.http.json(target.route.path, undefined, { jar: session.jar, csrfToken: csrf, raw: `{"constructor":{"prototype":{"polluted":true}},${rest}` }));
    }
    for (const res of checks) {
      if (res.status >= 500) return fail(expected, `${res.request.method} ${res.request.path} crashed with ${res.status}`, res);
      if (res.status !== 400) return fail(expected, `${res.request.method} ${res.request.path} answered ${res.status}`, res);
    }
    return pass(expected, `${checks.length} requests answered 400`, checks[0]);
  },
};

export const inputUnknownField: ProbeModule = {
  id: 'dast.input.unknown-field',
  group: 'input',
  requirementIds: ['V2.2.1', 'V15.3.3'],
  fallback: {
    title: 'Unknown fields are accepted',
    severity: 'medium',
    cwe: ['CWE-915'],
    description: 'A request with a field the route does not declare was accepted instead of answering 400.',
    impact: 'Extra fields can reach the database (mass assignment) and change data the user should not control.',
    fix: 'Use strict zod object schemas for every route so unknown fields are rejected.',
  },
  async run(ctx) {
    const expected = 'a sign-in form with an extra field, and a JSON create with an extra field, answer 400';
    const { token, jar } = await loginCsrf(ctx);
    const form = await ctx.http.form(ctx.paths.login, { _csrf: token ?? '', email: 'probe@test.local', password: 'not-a-real-password-1', isAdmin: '1' }, { jar });
    if (form.status !== 400) return fail(expected, `sign-in with an extra field answered ${form.status}`, form);
    const target = jsonCreateRoute(ctx);
    const session = ctx.sessions.get('member');
    if (target && session) {
      const csrf = await ctx.csrf(session);
      const res = await ctx.http.json(target.route.path, { ...target.body, ownerId: 'someone-else', isAdmin: true }, { jar: session.jar, csrfToken: csrf });
      if (res.status !== 400) return fail(expected, `${target.route.path} with extra fields answered ${res.status}`, res);
      return pass(expected, 'form and JSON create both answered 400', res);
    }
    return pass(expected, 'sign-in form answered 400 (no JSON create route to check)', form);
  },
};

export const inputTypeConfusion: ProbeModule = {
  id: 'dast.input.type-confusion',
  group: 'input',
  requirementIds: ['V2.2.2', 'V15.3.5'],
  fallback: {
    title: 'Wrong value types are accepted',
    severity: 'medium',
    cwe: ['CWE-843'],
    description: 'Sending an array or object where a string is expected was not refused with 400.',
    impact: 'Type confusion bypasses checks that assume strings and can crash handlers or alter queries.',
    fix: 'Validate every field with typed zod schemas; arrays where scalars are expected must be 400.',
  },
  async run(ctx) {
    const expected = 'arrays/objects in place of strings answer 400, never 500';
    const { token, jar } = await loginCsrf(ctx);
    const checks: HttpResponse[] = [];
    checks.push(await ctx.http.request(ctx.paths.login, { method: 'POST', jar, headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: `${formBody({ _csrf: token ?? '' })}&email[]=a%40test.local&password=not-a-real-password-1` }));
    checks.push(await ctx.http.json(ctx.paths.login, { _csrf: token ?? '', email: ['a@test.local'], password: { $gt: '' } }, { jar }));
    const target = jsonCreateRoute(ctx);
    const session = ctx.sessions.get('member');
    if (target && session) {
      const csrf = await ctx.csrf(session);
      const wrong: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(target.body)) wrong[k] = typeof v === 'string' ? [v] : v;
      checks.push(await ctx.http.json(target.route.path, wrong, { jar: session.jar, csrfToken: csrf }));
      checks.push(await ctx.http.json(target.route.path, Object.fromEntries(Object.keys(target.body).map((k) => [k, { $ne: null }])), { jar: session.jar, csrfToken: csrf }));
    }
    for (const res of checks) {
      if (res.status >= 500) return fail(expected, `${res.request.path} crashed with ${res.status}`, res);
      if (!rejected(res.status)) return fail(expected, `${res.request.path} answered ${res.status}`, res);
    }
    return pass(expected, `${checks.length} requests rejected with 4xx`, checks[0]);
  },
};

const INJECTION_STRINGS = ["'", '" OR 1=1--', "' OR '1'='1", '1; DROP TABLE users--'];

/**
 * Routes the smoke tests may hammer. The sign-out route is left out on purpose: calling it would end the
 * session the later probes in this group depend on, and it proves nothing about input handling.
 */
function probeRoutes(ctx: ProbeContext): RouteInfo[] {
  return routesOf(ctx).filter(
    (r) => !isTestEndpoint(r.path) && r.path !== '/healthz' && r.path !== '/readyz' && r.path !== ctx.paths.logout,
  );
}

export const inputSqlSmoke: ProbeModule = {
  id: 'dast.input.sql-smoke',
  group: 'input',
  requirementIds: ['V1.2.4', 'V16.5.1'],
  fallback: {
    title: 'Injection strings cause server errors',
    severity: 'high',
    cwe: ['CWE-89'],
    description: 'Sending quote characters and SQL fragments in a parameter made the app answer 500.',
    impact: 'A 500 on quote characters usually means the value reaches a query unparameterised.',
    fix: 'Use the db wrapper with parameters for every query and validate inputs first.',
  },
  async run(ctx) {
    const expected = "quote characters and SQL fragments in every string parameter never cause 500";
    const failures: ProbeFailure[] = [];
    let checked = 0;
    const member = ctx.sessions.get('member');
    for (const route of probeRoutes(ctx)) {
      for (const payload of INJECTION_STRINGS) {
        const jar = route.auth === 'public' ? undefined : member?.jar;
        if (route.auth !== 'public' && !jar) continue;
        const path = hasParams(route) ? fillPath(route.path, {}, payload) : `${route.path}?q=${encodeURIComponent(payload)}`;
        let res: HttpResponse;
        if (route.method === 'GET') res = await ctx.http.get(path, { jar });
        else {
          const csrf = jar ? await ctx.csrf(member) : undefined;
          const body: Record<string, unknown> = { title: payload, body: payload, email: `${payload}@test.local`, password: payload, code: payload, message: payload, name: payload };
          res = route.kind === 'api' || route.path.startsWith('/api/')
            ? await ctx.http.json(path, body, { method: route.method, jar, csrfToken: csrf })
            : await ctx.http.form(path, { ...(csrf ? { _csrf: csrf } : {}), title: payload, email: `${payload}@test.local`, password: payload }, { method: route.method, jar });
        }
        checked++;
        if (res.status >= 500 || leaksTechnicalDetail(res.body)?.includes('database')) failures.push(failureFrom(res, `status ${res.status}`));
      }
    }
    return summarize(expected, checked, failures);
  },
};

export const inputPathTraversalSmoke: ProbeModule = {
  id: 'dast.input.path-traversal-smoke',
  group: 'input',
  requirementIds: ['V1.3.4', 'V13.4.1'],
  fallback: {
    title: 'Path traversal not blocked',
    severity: 'high',
    cwe: ['CWE-22'],
    description: 'A path containing ../ segments returned file content or a server error instead of 400/404.',
    impact: 'Attackers read files outside the intended folder, including secrets.',
    fix: 'Never build file paths from user input; validate ids with strict schemas and serve files by database id only.',
  },
  async run(ctx) {
    const expected = '../ sequences in path parameters and static paths answer 400 or 404 without file content';
    const failures: ProbeFailure[] = [];
    let checked = 0;
    const attempts = ['../../.env', '..%2F..%2F.env', '....//....//.env', '%2e%2e/%2e%2e/package.json'];
    const member = ctx.sessions.get('member');
    const targets: { path: string; jar?: CookieJar }[] = attempts.map((a) => ({ path: `/css/${a}` }));
    for (const route of probeRoutes(ctx).filter((r) => r.method === 'GET' && hasParams(r))) {
      for (const a of attempts) targets.push({ path: route.path.replace(/:[A-Za-z0-9_]+\??/g, a), jar: route.auth === 'public' ? undefined : member?.jar });
    }
    for (const t of targets) {
      const res = await ctx.http.get(t.path, { jar: t.jar });
      checked++;
      if (res.status >= 500) failures.push(failureFrom(res, `status ${res.status}`));
      else if (res.status === 200 && /SESSION_SECRET=|"dependencies"\s*:|"scripts"\s*:/.test(res.body)) failures.push(failureFrom(res, 'file content returned'));
    }
    return summarize(expected, checked, failures);
  },
};

export const apiJsonContentType: ProbeModule = {
  id: 'dast.api.json-content-type',
  group: 'input',
  requirementIds: ['V4.1.1', 'V13.4.4'],
  fallback: {
    title: 'API responses without JSON content type',
    severity: 'low',
    cwe: ['CWE-436'],
    description: 'An API endpoint answered without Content-Type: application/json; charset=utf-8, or accepted a non-JSON body.',
    impact: 'Browsers may interpret API output as HTML, and lax request parsing enables cross-site tricks.',
    fix: 'Answer every /api route with res.json and accept only application/json bodies.',
  },
  async run(ctx) {
    const expected = 'API responses (including 404) are application/json; charset=utf-8 and a text/plain body is refused';
    const notFound = await ctx.http.get('/api/no-such-endpoint-securevibe');
    if (!/application\/json;\s*charset=utf-8/i.test(notFound.contentType())) return fail(expected, `API 404 sent "${notFound.contentType()}"`, notFound);
    const target = jsonCreateRoute(ctx);
    const session = ctx.sessions.get('member');
    if (target && session) {
      const csrf = await ctx.csrf(session);
      const plain = await ctx.http.request(target.route.path, { method: 'POST', jar: session.jar, headers: { 'Content-Type': 'text/plain', 'X-CSRF-Token': csrf ?? '' }, body: JSON.stringify(target.body) });
      if (plain.status < 400) return fail(expected, `${target.route.path} accepted a text/plain body (${plain.status})`, plain);
      if (!/application\/json/i.test(plain.contentType())) return fail(expected, `${target.route.path} error was not JSON`, plain);
      return pass(expected, 'JSON error model on 404 and on a refused text/plain body', plain);
    }
    return pass(expected, 'API 404 is JSON with charset (no create route to check bodies)', notFound);
  },
};

export const apiIdempotencyKey: ProbeModule = {
  id: 'dast.api.idempotency-key',
  group: 'input',
  requirementIds: ['RR-05', 'DM-03'],
  fallback: {
    title: 'Idempotency-Key not honoured',
    severity: 'low',
    cwe: ['CWE-799'],
    description: 'Repeating a JSON create with the same Idempotency-Key created a second record or answered differently.',
    impact: 'A retried request (network glitch, double click) creates duplicate records or charges.',
    fix: 'Mark JSON API mutations idempotent: true so the registry stores and replays the first response.',
  },
  async run(ctx) {
    const route = routesOf(ctx).find((r) => r.idempotent && r.method === 'POST' && r.auth === 'user' && !hasParams(r));
    const session = ctx.sessions.get('member');
    if (!route || !session) return NOT_ATTEMPTED(route ? 'no signed-in session' : 'no idempotent JSON API route is registered');
    const expected = `POST ${route.path} twice with the same Idempotency-Key returns the same response (replayed) once`;
    const csrf = await ctx.csrf(session);
    const key = `probe-${Date.now()}`;
    const body = bodyGuess(route);
    const first = await ctx.http.json(route.path, body, { jar: session.jar, csrfToken: csrf, headers: { 'Idempotency-Key': key } });
    const second = await ctx.http.json(route.path, body, { jar: session.jar, csrfToken: csrf, headers: { 'Idempotency-Key': key } });
    if (first.status >= 400) return NOT_ATTEMPTED(`the first create answered ${first.status}`, expected);
    if (second.status !== first.status || second.body !== first.body) return fail(expected, `second call answered ${second.status} with a different body`, second);
    if (!/true/i.test(second.header('idempotent-replayed') ?? '')) return fail(expected, 'same body but no Idempotent-Replayed header (cannot tell it was replayed)', second);
    return pass(expected, 'second call was replayed with Idempotent-Replayed: true', second);
  },
};

export const apikeyQueryStringRejected: ProbeModule = {
  id: 'dast.apikey.query-string-rejected',
  group: 'input',
  requirementIds: ['V14.2.1', 'V8.2.1'],
  fallback: {
    title: 'API keys accepted in the URL',
    severity: 'medium',
    cwe: ['CWE-598'],
    description: 'An API key passed as a query parameter was not refused with 400.',
    impact: 'Keys in URLs end up in logs, browser history and referrers.',
    fix: 'Accept API keys only in the Authorization: Bearer header and answer 400 for api_key query parameters.',
  },
  async run(ctx) {
    if (!ctx.features.publicApi) return NOT_ATTEMPTED('the public API feature is not enabled');
    const route = routesOf(ctx).find((r) => r.method === 'GET' && r.path.startsWith('/api/v1') && !hasParams(r));
    if (!route) return NOT_ATTEMPTED('no /api/v1 GET route is registered');
    const expected = `${route.path}?api_key=… answers 400`;
    const res = await ctx.http.get(`${route.path}?api_key=sk_probe_${'a'.repeat(32)}`);
    return res.status === 400 ? pass(expected, 'status 400', res) : fail(expected, `status ${res.status}`, res);
  },
};

export const inputProbes: ProbeModule[] = [
  inputOversizedBody,
  inputDuplicateParam,
  inputProtoPollution,
  inputUnknownField,
  inputTypeConfusion,
  inputSqlSmoke,
  inputPathTraversalSmoke,
  apiJsonContentType,
  apiIdempotencyKey,
  apikeyQueryStringRejected,
];
