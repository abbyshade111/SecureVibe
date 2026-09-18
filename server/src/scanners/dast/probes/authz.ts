/**
 * Authorization probes over the route registry export: every non-public route as anonymous, as a wrong role and
 * (for owner-scoped routes) as a non-owner; plus the live-vs-manifest comparison.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { HttpResponse } from '../http.js';
import { isDenied, isMutating, NOT_ATTEMPTED, type ProbeContext, type ProbeFailure, type ProbeModule, type RouteInfo, type Session } from '../types.js';
import { bodyGuess, failureFrom, fillPath, isTestEndpoint, routesOf, summarize } from './util.js';

function protectedRoutes(ctx: ProbeContext): RouteInfo[] {
  return routesOf(ctx).filter((r) => r.auth !== 'public' && !isTestEndpoint(r.path));
}

function sampleValues(ctx: ProbeContext, route: RouteInfo): Record<string, string> {
  const values: Record<string, string> = {};
  if (route.owner) {
    const entity = ctx.routes?.entities.find((e) => e.name === route.owner?.entity);
    if (entity?.sample.id !== null && entity?.sample.id !== undefined) values[route.owner.param] = String(entity.sample.id);
  }
  return values;
}

async function call(ctx: ProbeContext, route: RouteInfo, session: Session | undefined, values: Record<string, string>): Promise<HttpResponse> {
  const path = fillPath(route.path, values, '00000000-0000-4000-8000-000000000001');
  const jar = session?.jar;
  if (!isMutating(route.method)) return ctx.http.get(path, { jar, headers: { Accept: route.kind === 'api' ? 'application/json' : 'text/html' } });
  const csrf = session ? await ctx.csrf(session) : undefined;
  if (route.kind === 'api' || route.path.startsWith('/api/')) {
    return ctx.http.json(path, bodyGuess(route), { method: route.method, jar, csrfToken: csrf });
  }
  return ctx.http.form(path, { ...(csrf ? { _csrf: csrf } : {}), ...Object.fromEntries(Object.entries(bodyGuess(route)).map(([k, v]) => [k, String(v)])) }, { method: route.method, jar });
}

/** True when the response shows the request was refused before doing anything. */
function denied(res: HttpResponse, kind: RouteInfo['kind']): boolean {
  if (kind === 'api' || res.request.path.startsWith('/api/')) return res.status === 401 || res.status === 403 || res.status === 404;
  return isDenied(res.status);
}

export const authzAnonymousDenied: ProbeModule = {
  id: 'dast.authz.anonymous-denied',
  group: 'authz',
  requirementIds: ['V8.2.1', 'V8.3.1'],
  fallback: {
    title: 'A protected route is open to anonymous visitors',
    severity: 'critical',
    cwe: ['CWE-306'],
    description: 'A route declared as requiring sign-in answered a request that carried no session.',
    impact: 'Anyone on the network can read or change data that should need an account.',
    fix: 'Register the route with auth: "user" or "role:…" so requireAuth runs before the handler.',
  },
  async run(ctx) {
    const routes = protectedRoutes(ctx);
    const expected = 'every non-public route answers 401/403 (API) or redirects to sign-in (pages) without a session';
    const failures: ProbeFailure[] = [];
    let checked = 0;
    for (const route of routes) {
      const res = await call(ctx, route, undefined, sampleValues(ctx, route));
      checked++;
      if (!denied(res, route.kind)) failures.push(failureFrom(res, `status ${res.status} without a session`));
    }
    return summarize(expected, checked, failures);
  },
};

function wrongRoleSession(ctx: ProbeContext, route: RouteInfo): Session | undefined {
  const adminRole = ctx.routes?.adminRole ?? 'admin';
  const allowed = new Set<string>();
  if (route.auth.startsWith('role:')) allowed.add(route.auth.slice(5));
  for (const r of route.roles ?? []) allowed.add(r);
  if (allowed.size === 0) return undefined; // any signed-in user may call it
  for (const label of ['member', 'member2', 'staff']) {
    const s = ctx.sessions.get(label);
    if (s && s.role !== adminRole && !allowed.has(s.role)) return s;
  }
  return undefined;
}

export const authzWrongRoleDenied: ProbeModule = {
  id: 'dast.authz.wrong-role-denied',
  group: 'authz',
  requirementIds: ['V8.2.1', 'V8.3.1'],
  fallback: {
    title: 'A role-restricted route is open to other roles',
    severity: 'critical',
    cwe: ['CWE-285'],
    description: 'A route restricted to a role (for example admin) answered a signed-in user with a different role.',
    impact: 'Ordinary users can perform administrator actions or read staff-only data.',
    fix: 'Declare the role on the route (auth: "role:admin" or roles: [...]) so requireRole runs server-side.',
  },
  async run(ctx) {
    const expected = 'role-restricted routes answer 403 (or 404) for a signed-in user with a different role';
    const failures: ProbeFailure[] = [];
    let checked = 0;
    for (const route of protectedRoutes(ctx)) {
      const session = wrongRoleSession(ctx, route);
      if (!session) continue;
      const res = await call(ctx, route, session, sampleValues(ctx, route));
      checked++;
      if (!(res.status === 403 || res.status === 404 || (route.kind !== 'api' && res.isRedirect()))) failures.push(failureFrom(res, `status ${res.status} for role ${session.role}`));
    }
    if (checked === 0) return NOT_ATTEMPTED('no role-restricted route could be tested with a signed-in user of another role', expected);
    return summarize(expected, checked, failures);
  },
};

export const authzNonOwnerDenied: ProbeModule = {
  id: 'dast.authz.non-owner-denied',
  group: 'authz',
  requirementIds: ['V8.2.2'],
  fallback: {
    title: "Another user's record is accessible",
    severity: 'high',
    cwe: ['CWE-639'],
    description: 'A signed-in user could read or change a record owned by a different user by using its id.',
    impact: 'Customers can see each other’s data (insecure direct object reference).',
    fix: 'Add owner: { entity, param } to the route so requireOwner checks the record’s owner.',
  },
  async run(ctx) {
    const expected = 'owner-scoped routes answer 403/404 for a signed-in user who does not own the record';
    const other = ctx.sessions.get('member2');
    const owner = ctx.sessions.get('member');
    if (!other) return NOT_ATTEMPTED('the second member account could not sign in');
    const routes = protectedRoutes(ctx).filter((r) => r.owner);
    const failures: ProbeFailure[] = [];
    let checked = 0;
    let inconclusive = 0;
    // Read/list probes first so a DELETE by the non-owner (which must fail) cannot remove the sample before them.
    const ordered = [...routes].sort((a, b) => Number(isMutating(a.method)) - Number(isMutating(b.method)));
    for (const route of ordered) {
      const values = sampleValues(ctx, route);
      if (!values[route.owner!.param]) {
        inconclusive++;
        checked++;
        continue;
      }
      const res = await call(ctx, route, other, values);
      checked++;
      if (res.status === 403 || res.status === 404 || (route.kind !== 'api' && res.isRedirect())) continue;
      if (res.status >= 200 && res.status < 300) {
        failures.push(failureFrom(res, `status ${res.status} for a non-owner`));
        continue;
      }
      // 400/422 etc.: validation stopped the request before the owner check; nothing proven either way.
      inconclusive++;
    }
    if (owner && routes.length > 0 && failures.length === 0) {
      // Sanity check that the owner can still read: otherwise "denied" could just mean "broken".
      const read = routes.find((r) => r.method === 'GET');
      if (read) {
        const res = await call(ctx, read, owner, sampleValues(ctx, read));
        if (res.status >= 400) inconclusive = checked; // cannot trust the denials
      }
    }
    return summarize(expected, checked, failures, inconclusive);
  },
};

interface ManifestRoute {
  method: string;
  path: string;
}

export function readRoutesManifest(appDir: string): ManifestRoute[] | undefined {
  const file = join(appDir, 'routes.manifest.json');
  if (!existsSync(file)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as unknown;
    const list = Array.isArray(parsed) ? parsed : (parsed as { routes?: unknown[] })?.routes;
    if (!Array.isArray(list)) return undefined;
    return list.filter((r): r is ManifestRoute => Boolean(r) && typeof (r as ManifestRoute).method === 'string' && typeof (r as ManifestRoute).path === 'string');
  } catch {
    return undefined;
  }
}

export const authzUnregisteredRoute: ProbeModule = {
  id: 'dast.authz.unregistered-route',
  group: 'authz',
  requirementIds: ['V8.1.1', 'V8.2.1'],
  fallback: {
    title: 'Route with unknown authorization policy',
    severity: 'high',
    cwe: ['CWE-862'],
    description: 'A route is live in the app but is missing from routes.manifest.json, so its access policy was never declared for review.',
    impact: 'Undeclared routes escape the authorization documentation and the design review.',
    fix: 'Run npm run routes:export (or add the route to routes.manifest.json) and review its auth value.',
  },
  async run(ctx) {
    const manifest = readRoutesManifest(ctx.appDir);
    const expected = 'every live route (except health and test endpoints) is listed in routes.manifest.json';
    if (!manifest) return NOT_ATTEMPTED('routes.manifest.json is missing or unreadable; run npm run routes:export', expected);
    const listed = new Set(manifest.map((r) => `${r.method.toUpperCase()} ${r.path}`));
    const live = routesOf(ctx).filter((r) => !isTestEndpoint(r.path) && r.path !== '/healthz' && r.path !== '/readyz');
    const missing = live.filter((r) => !listed.has(`${r.method} ${r.path}`));
    if (missing.length === 0) return { passed: true, expected, observed: `${live.length} live routes all listed` };
    return {
      passed: false,
      expected,
      observed: `${missing.length} live route(s) not in the manifest: ${missing.map((r) => `${r.method} ${r.path}`).join(', ')}`,
      failures: missing.map((r) => ({ endpoint: `${r.method} ${r.path}`, observed: `live route with auth "${r.auth}" is not declared in routes.manifest.json` })),
    };
  },
};

export const authzProbes: ProbeModule[] = [authzAnonymousDenied, authzWrongRoleDenied, authzNonOwnerDenied, authzUnregisteredRoute];
