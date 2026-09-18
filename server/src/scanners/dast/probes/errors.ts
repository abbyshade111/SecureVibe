/**
 * Error-handling probes: no stack traces or technical detail, generic 404/500 bodies, 405 for wrong methods.
 */
import type { HttpResponse } from '../http.js';
import { NOT_ATTEMPTED, type ProbeContext, type ProbeModule } from '../types.js';
import { fail, leaksTechnicalDetail, pass } from './util.js';

/** Requests that make well-behaved apps answer 4xx and badly behaved ones answer 500 with a stack. */
async function hostileRequests(ctx: ProbeContext): Promise<HttpResponse[]> {
  return Promise.all([
    ctx.http.get('/no-such-page-securevibe'),
    ctx.http.get('/api/no-such-endpoint-securevibe'),
    ctx.http.json(ctx.paths.login, undefined, { raw: '{"email": ' }),
    ctx.http.request(ctx.paths.login, { method: 'POST', headers: { 'Content-Type': 'application/json; charset=utf-7' }, body: '{}' }),
    ctx.http.request(ctx.paths.login, { method: 'PUT' }),
    ctx.http.get(`${ctx.paths.login}?next=%ff%fe`),
    ctx.http.get('/%'),
  ]);
}

export const errorsNoStackTrace: ProbeModule = {
  id: 'dast.errors.no-stack-trace',
  group: 'errors',
  requirementIds: ['V16.5.1', 'V16.5.3'],
  fallback: {
    title: 'Error responses reveal technical details',
    severity: 'medium',
    cwe: ['CWE-209'],
    description: 'An error response contained a stack trace, file path, database error or framework default page.',
    impact: 'Attackers learn file names, library versions and query shapes that make other attacks easier.',
    fix: 'Send only the generic error model ({error:{code,message}} or the error page) and log details server-side.',
  },
  async run(ctx) {
    const expected = 'no error response contains stack traces, file paths, database errors or framework default pages';
    const responses = await hostileRequests(ctx);
    for (const res of responses) {
      const leak = leaksTechnicalDetail(res.body);
      if (leak) return fail(expected, `${res.request.method} ${res.request.path} (status ${res.status}) contained ${leak}`, res);
    }
    return pass(expected, `${responses.length} error responses checked, all generic`, responses[0]);
  },
};

export const errors404Generic: ProbeModule = {
  id: 'dast.errors.404-generic',
  group: 'errors',
  requirementIds: ['V16.5.1'],
  fallback: {
    title: 'Not-found responses are not generic',
    severity: 'low',
    cwe: ['CWE-209'],
    description: 'A 404 response used the framework default page or echoed the requested path.',
    impact: 'Reflected paths can carry injected content, and default pages reveal the framework.',
    fix: 'Use the template’s 404 handler: a fixed page for HTML and {error:{code:"not_found"}} for the API.',
  },
  async run(ctx) {
    const marker = `svprobe-${Date.now()}`;
    const expected = 'unknown paths answer 404 with a generic page/JSON that does not echo the path';
    const page = await ctx.http.get(`/no-such-page-${marker}`);
    const api = await ctx.http.get(`/api/no-such-endpoint-${marker}`, { headers: { Accept: 'application/json' } });
    if (page.status !== 404) return fail(expected, `unknown page answered ${page.status}`, page);
    if (page.body.includes(marker)) return fail(expected, 'the requested path is echoed in the 404 page', page);
    if (/Cannot GET/.test(page.body)) return fail(expected, "Express's default 'Cannot GET' page", page);
    if (api.status !== 404) return fail(expected, `unknown API path answered ${api.status}`, api);
    const json = api.json<{ error?: { code?: string } }>();
    if (!json?.error?.code) return fail(expected, 'API 404 is not the JSON error model', api);
    return pass(expected, `404 page is generic; API 404 is {error:{code:"${json.error.code}"}}`, api);
  },
};

export const errors500Generic: ProbeModule = {
  id: 'dast.errors.500-generic',
  group: 'errors',
  requirementIds: ['V16.5.1', 'V16.5.3'],
  fallback: {
    title: 'Server error responses are not generic',
    severity: 'medium',
    cwe: ['CWE-209', 'CWE-756'],
    description: 'A 500 response contained technical details instead of the generic error model.',
    impact: 'Unexpected errors leak internals and may fail open.',
    fix: 'Keep the final error handler that answers a fixed message with code "internal_error".',
  },
  async run(ctx) {
    const expected = 'if any request causes a 500, the body is the generic error model without technical detail';
    const responses = await hostileRequests(ctx);
    const failing = responses.filter((r) => r.status >= 500);
    if (failing.length === 0) return NOT_ATTEMPTED('no request produced a server error, so the generic 500 body could not be observed', expected);
    for (const res of failing) {
      const leak = leaksTechnicalDetail(res.body);
      if (leak) return fail(expected, `${res.request.method} ${res.request.path} answered ${res.status} containing ${leak}`, res);
      const json = res.json<{ error?: { code?: string } }>();
      if (/application\/json/.test(res.contentType()) && json?.error?.code !== 'internal_error') return fail(expected, `500 JSON body is not the error model: ${res.body.slice(0, 80)}`, res);
    }
    return pass(expected, `${failing.length} server error(s) had generic bodies`, failing[0]);
  },
};

export const errorsMethodNotAllowed: ProbeModule = {
  id: 'dast.errors.method-not-allowed',
  group: 'errors',
  requirementIds: ['V13.4.4'],
  fallback: {
    title: 'Wrong HTTP methods are not refused with 405',
    severity: 'low',
    cwe: ['CWE-749'],
    description: 'A known path answered a method it does not support with something other than 405 (and an Allow header).',
    impact: 'Sloppy method handling hides bugs and can let unexpected handlers run.',
    fix: 'Answer 405 with an Allow header for known paths and unsupported methods.',
  },
  async run(ctx) {
    const expected = `PUT ${ctx.paths.login} and DELETE / answer 405 with an Allow header`;
    const put = await ctx.http.request(ctx.paths.login, { method: 'PUT' });
    const del = await ctx.http.request('/', { method: 'DELETE' });
    for (const res of [put, del]) {
      if (res.status !== 405) return fail(expected, `${res.request.method} ${res.request.path} answered ${res.status}`, res);
      if (!res.header('allow')) return fail(expected, `${res.request.method} ${res.request.path} answered 405 without Allow`, res);
    }
    return pass(expected, `405 with Allow: ${put.header('allow')}`, put);
  },
};

export const errorProbes: ProbeModule[] = [errorsNoStackTrace, errors404Generic, errors500Generic, errorsMethodNotAllowed];
