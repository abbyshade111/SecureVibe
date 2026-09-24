/**
 * The probe runner: turns a started app into a ProbeContext (route registry export, signed-in cookie jars per
 * seeded role, CSRF tokens, security events) and executes the probe modules in the CONTRACTS §2 group order.
 *
 * Rules that matter for honesty: a probe that throws or cannot set up its preconditions records `passed: null`
 * with a reason — never `true`. Rate-limit probes run last and the limiters are reset before each of them, so one
 * probe exhausting a budget cannot make the next one look broken.
 */
import type { BuildSpec } from '@shared/design.js';
import { formAuthBootstrap, type AuthBootstrapContext, type DastAuthBootstrap } from './auth.js';
import { CookieJar, extractCsrfToken, HttpClient } from './http.js';
import { ALL_PROBES } from './probes/index.js';
import { totp } from './totp.js';
import {
  PROBE_GROUPS,
  type AppInstance,
  type ProbeContext,
  type ProbeGroup,
  type ProbeModule,
  type ProbePhase,
  type ProbeResult,
  type RoutesExport,
  type SecurityEvent,
  type SeededUser,
  type Session,
} from './types.js';
import type { TemplateManifest } from '@shared/knowledge.js';

/** Contract defaults used when the route registry export does not name a route we need. */
export const DEFAULT_PATHS = {
  login: '/login',
  loginMfa: '/login/mfa',
  logout: '/logout',
  account: '/account',
  changePassword: '/account/password',
  forgotPassword: '/forgot-password',
  register: '/register',
  aiKillSwitch: '/admin/ai/kill-switch',
};

export interface RoutesFetch {
  routes: RoutesExport | undefined;
  /** Why the export could not be read (for the not-attempted reasons of route-driven probes). */
  problem?: string;
}

function asRoutesExport(value: unknown): RoutesExport | undefined {
  if (!value || typeof value !== 'object') return undefined;
  const raw = value as Partial<RoutesExport>;
  if (!Array.isArray(raw.routes)) return undefined;
  return {
    routes: raw.routes.filter((r) => Boolean(r) && typeof r.path === 'string' && typeof r.method === 'string'),
    roles: Array.isArray(raw.roles) ? raw.roles : [],
    adminRole: raw.adminRole ?? (Array.isArray(raw.roles) && raw.roles.includes('admin') ? 'admin' : raw.roles?.[0]),
    entities: Array.isArray(raw.entities) ? raw.entities : [],
    seededUsers: Array.isArray(raw.seededUsers) ? raw.seededUsers : undefined,
  };
}

export async function fetchRoutes(http: HttpClient, endpoint: string): Promise<RoutesFetch> {
  try {
    const res = await http.get(endpoint, { headers: { Accept: 'application/json' } });
    if (res.status !== 200) return { routes: undefined, problem: `${endpoint} answered ${res.status}` };
    const parsed = asRoutesExport(res.json());
    if (!parsed) return { routes: undefined, problem: `${endpoint} did not return { routes: [...] }` };
    return { routes: parsed };
  } catch (err) {
    return { routes: undefined, problem: `${endpoint} could not be reached: ${(err as Error).message}` };
  }
}

function pathOf(routes: RoutesExport | undefined, pred: (path: string) => boolean, method = 'GET'): string | undefined {
  return routes?.routes.find((r) => r.method === method && !/:[A-Za-z0-9_]/.test(r.path) && pred(r.path))?.path;
}

function hasRoute(routes: RoutesExport | undefined, pred: (path: string) => boolean, method: string): boolean {
  return Boolean(routes?.routes.some((r) => r.method === method && pred(r.path)));
}

/** Ready-made request paths derived from the registry, falling back to the template's own route names. */
export function derivePaths(routes: RoutesExport | undefined): ProbeContext['paths'] {
  const exists = (p: string | undefined, method: string): string | undefined =>
    p && hasRoute(routes, (path) => path === p, method) ? p : undefined;
  const login = pathOf(routes, (p) => /(^|\/)(login|sign-?in)$/.test(p)) ?? DEFAULT_PATHS.login;
  const loginMfa = pathOf(routes, (p) => /(mfa|totp|2fa|one-time)/.test(p) && p.startsWith(login), 'POST') ?? DEFAULT_PATHS.loginMfa;
  const logout = pathOf(routes, (p) => /(^|\/)(logout|sign-?out)$/.test(p), 'POST') ?? DEFAULT_PATHS.logout;
  const account = pathOf(routes, (p) => p === '/account') ?? DEFAULT_PATHS.account;
  const register =
    pathOf(routes, (p) => /(^|\/)(register|sign-?up)$/.test(p), 'POST') ??
    (routes ? undefined : DEFAULT_PATHS.register);
  const forgotPassword =
    pathOf(routes, (p) => /forgot|reset-request|password\/reset$/.test(p), 'POST') ??
    (routes ? undefined : DEFAULT_PATHS.forgotPassword);
  const changePassword =
    pathOf(routes, (p) => /password$/.test(p) && !/forgot|reset/.test(p), 'POST') ??
    (routes ? undefined : DEFAULT_PATHS.changePassword);
  const uploads = pathOf(routes, (p) => /(^|\/)uploads?$/.test(p), 'POST');
  const ai = pathOf(routes, (p) => /(^|\/)ai(\/(ask|chat|message))?$/.test(p), 'POST');
  const aiKillSwitch = exists(DEFAULT_PATHS.aiKillSwitch, 'POST') ?? pathOf(routes, (p) => /kill-switch/.test(p), 'POST');
  const adminPage = routes?.routes.find(
    (r) => r.method === 'GET' && r.kind !== 'api' && /^role:/.test(r.auth) && !/:[A-Za-z0-9_]/.test(r.path),
  )?.path;
  const notesApi = pathOf(routes, (p) => /^\/api\/.+/.test(p), 'POST');
  return { login, loginMfa, logout, account, register, forgotPassword, changePassword, uploads, ai, aiKillSwitch, adminPage, notesApi };
}

export interface BuildContextOptions {
  app: AppInstance;
  appDir: string;
  buildSpec: BuildSpec;
  testMode?: TemplateManifest['testMode'];
  auth?: DastAuthBootstrap;
  /** Replaces the loopback HTTP client (the scanner's own tests drive an app running in this process). */
  http?: HttpClient;
  /** The app's routes when it cannot export them in test mode (SecureVibe's self-assessment). */
  routes?: RoutesExport;
  log(msg: string): void;
}

export interface DastContextBuild {
  ctx: ProbeContext;
  routesProblem?: string;
  /** Labels of seeded users that could not sign in (reported in the scan summary). */
  signInFailures: string[];
}

/** Builds the ProbeContext for one started app: routes, sessions, helpers. */
export async function buildProbeContext(opts: BuildContextOptions): Promise<DastContextBuild> {
  const { app, buildSpec, log } = opts;
  const http = opts.http ?? new HttpClient(app.baseUrl);
  const bootstrap = opts.auth ?? formAuthBootstrap;
  const routesEndpoint = opts.testMode?.routesEndpoint ?? '/__securevibe/routes';

  const fetched: RoutesFetch = opts.routes
    ? { routes: opts.routes }
    : app.phase === 'test'
      ? await fetchRoutes(http, routesEndpoint)
      : { routes: undefined, problem: 'the route registry export only exists in test mode' };
  const paths = derivePaths(fetched.routes);
  const secrets = {
    password: app.env['SECUREVIBE_TEST_PASSWORD'] ?? '',
    totpSeed: app.env['SECUREVIBE_TEST_TOTP_SEED'] ?? '',
  };

  const authCtx: AuthBootstrapContext = {
    http,
    app,
    routes: fetched.routes,
    secrets,
    paths: { login: paths.login, loginMfa: paths.loginMfa, account: paths.account },
    log,
  };

  const seededUsers: SeededUser[] = app.phase === 'test' ? bootstrap.seededUsers(authCtx, opts.testMode) : [];
  const sessions = new Map<string, Session>();
  const signInFailures: string[] = [];

  const ctx: ProbeContext = {
    phase: app.phase,
    app,
    http,
    buildSpec,
    features: buildSpec.features,
    appDir: opts.appDir,
    routes: fetched.routes,
    seededUsers,
    sessions,
    secrets,
    paths,

    async csrf(session, fromPath) {
      const from = fromPath ?? (session ? paths.account : paths.login);
      const res = await http.get(from, { jar: session?.jar });
      const token = extractCsrfToken(res.body);
      if (token && session) session.csrfToken = token;
      return token ?? session?.csrfToken;
    },

    async events(sinceIso) {
      if (app.phase !== 'test') return [];
      try {
        const res = await http.get(`/__securevibe/events?since=${encodeURIComponent(sinceIso)}`, { headers: { Accept: 'application/json' } });
        const body = res.json<{ events?: SecurityEvent[] } | SecurityEvent[]>();
        const list = Array.isArray(body) ? body : (body?.events ?? []);
        return list.filter((e): e is SecurityEvent => Boolean(e) && typeof e === 'object' && typeof (e as SecurityEvent).event === 'string');
      } catch {
        return [];
      }
    },

    async resetRateLimits() {
      if (app.resetRateLimits) return app.resetRateLimits();
      if (app.phase !== 'test') return false;
      try {
        const res = await http.request('/__securevibe/reset-rate-limits', { method: 'POST' });
        return res.status >= 200 && res.status < 300;
      } catch {
        return false;
      }
    },

    async login(label) {
      const user = seededUsers.find((u) => u.label === label);
      if (!user) return undefined;
      const session = await bootstrap.login(user, authCtx);
      if (!session) return undefined;
      return session;
    },

    loginAttempt(email, password, jar, headers) {
      return bootstrap.loginAttempt(email, password, authCtx, jar ?? new CookieJar(), headers ?? {});
    },

    totp(seedBase32) {
      return totp(seedBase32);
    },

    log,

    pageFor(auth) {
      const wanted = auth === 'admin' ? /^role:/ : /^user$/;
      const route = fetched.routes?.routes.find(
        (r) =>
          r.method === 'GET' &&
          r.kind !== 'api' &&
          wanted.test(r.auth) &&
          !/:[A-Za-z0-9_]/.test(r.path) &&
          !r.path.startsWith('/__securevibe') &&
          r.path !== paths.logout,
      );
      return route?.path;
    },
  };

  if (app.phase === 'test') {
    for (const user of seededUsers) {
      const session = await bootstrap.login(user, authCtx);
      if (session) sessions.set(user.label, session);
      else signInFailures.push(user.label);
    }
    log(`[dast] signed in ${sessions.size} of ${seededUsers.length} seeded accounts`);
  }

  return { ctx, routesProblem: fetched.problem, signInFailures };
}

export interface RunProbesOptions {
  probes?: ProbeModule[];
  /** Probes that do not apply to this app, with the reason; they are recorded as not attempted. */
  notApplicable?: Record<string, string>;
  abort?: AbortSignal;
  /** Called after every probe (progress logging). */
  onResult?(result: ProbeResult): void;
}

const groupRank = new Map<ProbeGroup, number>(PROBE_GROUPS.map((g, i) => [g, i]));

/**
 * Some probes end a session on purpose (they post to the sign-out route, or check that a cookie stops working).
 * Before each new group the shared sessions are checked and signed in again if needed, so a later probe never
 * reports "denied" when the real reason is that its account is no longer signed in.
 */
export async function refreshSessions(ctx: ProbeContext): Promise<string[]> {
  if (ctx.phase !== 'test') return [];
  const page = ctx.pageFor('user') ?? ctx.paths.account;
  const lost: string[] = [];
  for (const label of [...ctx.sessions.keys()]) {
    const session = ctx.sessions.get(label);
    if (!session) continue;
    let alive = false;
    try {
      alive = (await ctx.http.get(page, { jar: session.jar })).status === 200;
    } catch {
      alive = false;
    }
    if (alive) continue;
    const fresh = await ctx.login(label);
    if (fresh) ctx.sessions.set(label, fresh);
    else {
      ctx.sessions.delete(label);
      lost.push(label);
    }
  }
  return lost;
}

/** Runs the probes for one phase, in group order, resetting the limiters before every rate probe. */
export async function runProbes(ctx: ProbeContext, opts: RunProbesOptions = {}): Promise<ProbeResult[]> {
  const probes = (opts.probes ?? ALL_PROBES)
    .filter((p) => (p.phase ?? 'test') === ctx.phase)
    .sort((a, b) => (groupRank.get(a.group) ?? 99) - (groupRank.get(b.group) ?? 99));
  const results: ProbeResult[] = [];
  let previousGroup: ProbeGroup | undefined;

  for (const probe of probes) {
    const notApplicable = opts.notApplicable?.[probe.id];
    if (notApplicable) {
      const skipped: ProbeResult = { id: probe.id, group: probe.group, phase: ctx.phase, requirementIds: probe.requirementIds, passed: null, expected: '', observed: 'not attempted', reason: notApplicable, durationMs: 0 };
      results.push(skipped);
      opts.onResult?.(skipped);
      continue;
    }
    if (opts.abort?.aborted) {
      results.push({
        id: probe.id,
        group: probe.group,
        phase: ctx.phase,
        requirementIds: probe.requirementIds,
        passed: null,
        expected: '',
        observed: 'not attempted',
        reason: 'the run was canceled before this check could run',
        durationMs: 0,
      });
      continue;
    }
    // Every rate probe starts from a clean limiter, and so does the first probe after the rate group.
    if (probe.group === 'rate' || previousGroup === 'rate') await ctx.resetRateLimits();
    if (probe.group !== previousGroup) {
      const lost = await refreshSessions(ctx);
      for (const label of lost) ctx.log(`[dast] the ${label} account could not be signed in again before the ${probe.group} checks`);
    }
    previousGroup = probe.group;

    const started = Date.now();
    let result: ProbeResult;
    try {
      const outcome = await probe.run(ctx);
      result = { ...outcome, id: probe.id, group: probe.group, phase: ctx.phase, requirementIds: probe.requirementIds, durationMs: Date.now() - started };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      result = {
        id: probe.id,
        group: probe.group,
        phase: ctx.phase,
        requirementIds: probe.requirementIds,
        passed: null,
        expected: '',
        observed: 'not attempted',
        reason: `the check could not be completed: ${message}`,
        durationMs: Date.now() - started,
      };
    }
    results.push(result);
    opts.onResult?.(result);
  }
  return results;
}

/** Marks every probe of a phase as not attempted (used when that app start failed). */
export function notAttemptedForPhase(phase: ProbePhase, reason: string, probes: ProbeModule[] = ALL_PROBES): ProbeResult[] {
  return probes
    .filter((p) => (p.phase ?? 'test') === phase)
    .map((p) => ({
      id: p.id,
      group: p.group,
      phase,
      requirementIds: p.requirementIds,
      passed: null,
      expected: '',
      observed: 'not attempted',
      reason,
      durationMs: 0,
    }));
}
