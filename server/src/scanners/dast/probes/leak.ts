/**
 * Information-leak and health probes: dotfiles, directory listings, TRACE, minimal health endpoints, and the
 * production-mode checks that test-mode endpoints are gone and /readyz answers from loopback.
 */
import type { HttpResponse } from '../http.js';
import type { ProbeModule } from '../types.js';
import { fail, pass } from './util.js';

const SECRET_MARKERS = /SESSION_SECRET=|FIELD_KEYS=|TOKEN_HMAC_KEY=|ref: refs\/|\[core\]|ignore-scripts/;

async function tryPaths(get: (p: string) => Promise<HttpResponse>, paths: string[], isLeak: (r: HttpResponse) => string | undefined): Promise<{ leak?: { res: HttpResponse; why: string }; last?: HttpResponse }> {
  let last: HttpResponse | undefined;
  for (const p of paths) {
    const res = await get(p);
    last = res;
    const why = isLeak(res);
    if (why) return { leak: { res, why }, last };
  }
  return { last };
}

export const leakDotfiles: ProbeModule = {
  id: 'dast.leak.dotfiles',
  group: 'leak',
  requirementIds: ['V13.4.1', 'V13.4.3'],
  fallback: {
    title: 'Hidden files served over HTTP',
    severity: 'critical',
    cwe: ['CWE-538'],
    description: 'A request for a dotfile such as /.env or /.git/HEAD returned its content.',
    impact: 'Secrets and source history become readable by anyone who can reach the app.',
    fix: "Serve static files only from public/ with dotfiles: 'deny' and never place secrets under the web root.",
  },
  async run(ctx) {
    const expected = '/.env, /.git/HEAD, /.npmrc, /.gitignore, /.env.example answer 404 (or 403) without content';
    const { leak, last } = await tryPaths(
      (p) => ctx.http.get(p),
      ['/.env', '/.git/HEAD', '/.git/config', '/.npmrc', '/.gitignore', '/.env.example', '/.DS_Store'],
      (res) => {
        if (res.status === 200) return `answered 200 with ${res.body.length} bytes`;
        if (SECRET_MARKERS.test(res.body)) return 'response body contains file content';
        return undefined;
      },
    );
    return leak ? fail(expected, `${leak.res.request.path} ${leak.why}`, leak.res) : pass(expected, 'every dotfile request was refused', last);
  },
};

export const leakDirectoryListing: ProbeModule = {
  id: 'dast.leak.directory-listing',
  group: 'leak',
  requirementIds: ['V13.4.1'],
  fallback: {
    title: 'Directory listing enabled',
    severity: 'medium',
    cwe: ['CWE-548'],
    description: 'Requesting a folder path returned a list of its files.',
    impact: 'Attackers learn the names of every file and can find backups or forgotten files.',
    fix: 'Disable directory indexes (express.static with index: false, no serve-index).',
  },
  async run(ctx) {
    const expected = 'folder paths such as /css/, /js/, /public/, /static/ never list their files';
    const { leak, last } = await tryPaths(
      (p) => ctx.http.get(p),
      ['/css/', '/js/', '/public/', '/static/', '/assets/', '/uploads/'],
      (res) => (res.status === 200 && /Index of|<title>listing|<ul id="files"|directory listing/i.test(res.body) ? 'returned a directory listing' : undefined),
    );
    return leak ? fail(expected, `${leak.res.request.path} ${leak.why}`, leak.res) : pass(expected, 'no folder listing was returned', last);
  },
};

export const leakTrace: ProbeModule = {
  id: 'dast.leak.trace',
  group: 'leak',
  requirementIds: ['V13.4.4'],
  fallback: {
    title: 'TRACE method supported',
    severity: 'low',
    cwe: ['CWE-16'],
    description: 'The app answered an HTTP TRACE request instead of refusing it.',
    impact: 'TRACE can echo headers (including cookies) back to a script in some setups.',
    fix: 'Reject TRACE and other unusual methods with 405 before any route handling.',
  },
  async run(ctx) {
    const expected = 'TRACE / answers 405 (or 404/501) and never echoes the request';
    const res = await ctx.http.raw('TRACE', '/', { 'X-Securevibe-Probe': 'trace-echo' });
    if (res.status === 200 || /trace-echo/i.test(res.body)) return fail(expected, `status ${res.status}${/trace-echo/i.test(res.body) ? ', request echoed' : ''}`, res);
    return pass(expected, `status ${res.status}`, res);
  },
};

export const leakHealthMinimal: ProbeModule = {
  id: 'dast.leak.health-minimal',
  group: 'leak',
  requirementIds: ['V13.4.5'],
  fallback: {
    title: 'Health endpoint reveals internal details',
    severity: 'low',
    cwe: ['CWE-200'],
    description: '/healthz returned more than {"status":"ok"} (versions, hostnames, uptime or configuration).',
    impact: 'Version and environment details help attackers pick known exploits.',
    fix: 'Return only {"status":"ok"} from /healthz; keep details in logs.',
  },
  async run(ctx) {
    const expected = '/healthz returns exactly {"status":"ok"}';
    const res = await ctx.http.get('/healthz');
    const json = res.json<Record<string, unknown>>();
    if (res.status !== 200 || !json) return fail(expected, `status ${res.status}, body ${res.body.slice(0, 80)}`, res);
    const keys = Object.keys(json);
    if (keys.length === 1 && json['status'] === 'ok') return pass(expected, res.body.trim(), res);
    return fail(expected, `extra fields: ${keys.filter((k) => k !== 'status').join(', ') || `status=${String(json['status'])}`}`, res);
  },
};

export const healthHealthz: ProbeModule = {
  id: 'dast.health.healthz',
  group: 'leak',
  requirementIds: ['V13.4.5'],
  fallback: {
    title: 'Liveness endpoint missing',
    severity: 'low',
    cwe: ['CWE-1059'],
    description: '/healthz did not answer 200 with JSON.',
    impact: 'Operators cannot tell whether the app is alive without opening pages.',
    fix: 'Provide GET /healthz returning {"status":"ok"}.',
  },
  async run(ctx) {
    const expected = 'GET /healthz answers 200 with JSON {"status":"ok"}';
    const res = await ctx.http.get('/healthz');
    const json = res.json<{ status?: string }>();
    return res.status === 200 && json?.status === 'ok' ? pass(expected, 'answered 200 {"status":"ok"}', res) : fail(expected, `status ${res.status}`, res);
  },
};

export const healthReadyz: ProbeModule = {
  id: 'dast.health.readyz',
  group: 'leak',
  phase: 'production',
  requirementIds: ['RR-06'],
  fallback: {
    title: 'Readiness endpoint not working',
    severity: 'low',
    cwe: ['CWE-1059'],
    description: '/readyz did not answer {"status":"ready"} from this computer in production mode.',
    impact: 'A process manager cannot tell when the app can take traffic.',
    fix: 'Provide GET /readyz that checks the database and answers {"status":"ready"} (loopback only unless BIND_LAN).',
  },
  async run(ctx) {
    const expected = 'GET /readyz from loopback answers 200 {"status":"ready"} in production mode';
    const res = await ctx.http.get('/readyz');
    const json = res.json<{ status?: string }>();
    return res.status === 200 && json?.status === 'ready' ? pass(expected, 'answered 200 {"status":"ready"}', res) : fail(expected, `status ${res.status}, body ${res.body.slice(0, 80)}`, res);
  },
};

export const leakTestEndpointsAbsent: ProbeModule = {
  id: 'dast.leak.test-endpoints-absent',
  group: 'leak',
  phase: 'production',
  requirementIds: ['V13.4.1', 'V15.2.3'],
  fallback: {
    title: 'Test-mode endpoints reachable in production',
    severity: 'critical',
    cwe: ['CWE-489'],
    description: 'The /__securevibe test endpoints (route export, security events, rate-limit reset, run scheduled jobs) answered in production mode.',
    impact: 'Anyone could read security events, reset rate limits and learn every route of the app.',
    fix: 'Mount the test-mode router only when NODE_ENV=test and SECUREVIBE_TEST_MODE=1; refuse test mode in production.',
  },
  async run(ctx) {
    const expected =
      '/__securevibe/routes, /__securevibe/events, POST /__securevibe/reset-rate-limits and POST /__securevibe/run-jobs answer 404 in production mode';
    const checks = await Promise.all([
      ctx.http.get('/__securevibe/routes'),
      ctx.http.get('/__securevibe/events'),
      ctx.http.request('/__securevibe/reset-rate-limits', { method: 'POST' }),
      ctx.http.request('/__securevibe/run-jobs', { method: 'POST' }),
    ]);
    for (const res of checks) {
      if (res.status !== 404 && res.status !== 405) return fail(expected, `${res.request.method} ${res.request.path} answered ${res.status}`, res);
    }
    return pass(expected, 'all three answered 404', checks[0]);
  },
};

export const leakProbes: ProbeModule[] = [leakDotfiles, leakDirectoryListing, leakTrace, leakHealthMinimal, healthHealthz, healthReadyz, leakTestEndpointsAbsent];
