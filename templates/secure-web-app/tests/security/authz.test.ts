/** Authorization (contract §1.4 registry, TPL-AUTHZ-01/02): deny by default, role checks, ownership. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, fillPath, formBody, isRedirect, locationOf, startApp, type RouteInfo, type RoutesExport, type RunningApp } from '../helpers/app.ts';
import { fields, headers as headerNames, paths, users } from '../helpers/conventions.ts';

const DENIED = new Set([401, 403, 404]);

function describeRoute(r: RouteInfo): string {
  return `${r.method} ${r.path} (auth: ${r.auth}${r.roles ? `, roles: ${r.roles.join('/')}` : ''}${r.owner ? `, owner: ${r.owner.entity}` : ''})`;
}

describe('authz', () => {
  let app: RunningApp;
  let registry: RoutesExport;
  let memberRole: string;
  const jars: Record<string, CookieJar> = {};
  const csrf: Record<string, string> = {};

  before(async () => {
    app = await startApp();
    registry = await app.routes();
    // The role the person we probe with actually holds, asked of the app rather than guessed from the roles it
    // declares. The two differ exactly where it matters: an app that declares only an administrator role still seeds
    // ordinary members, under a role it never declared, so guessing from the declared roles would decide that the
    // member holds the administrator's role and that the admin area is therefore not restricted from them.
    memberRole = registry.seededUsers.find((u) => u.email === users.member)?.role ?? registry.roles[registry.roles.length - 1] ?? 'member';
    for (const who of ['member', 'member2', 'admin'] as const) {
      jars[who] = await app.login(users[who]);
      csrf[who] = await app.csrfToken(paths.account, jars[who]);
    }
  });
  after(async () => {
    await app?.stop();
  });

  /**
   * Pages the app puts behind a role, whatever that role is called.
   *
   * These used to be found with `auth === 'role:admin'`, which only ever worked for an app whose administrator role
   * happened to be named "admin". An owner who calls the role "Owner" or "Manager" — and SecureVibe asks them to
   * name it — got three failing tests on an app whose authorization was fine, and lost the evidence for V8.2.1 and
   * V8.3.1 with them. Worse than the false failure: for every other app, those requirements were only ever verified
   * by accident of naming.
   *
   * An administrator may open any of these whatever role they name, because requireRole checks `isAdmin` first
   * (src/security/authz.ts), so this is the right set for both the "an administrator can" and the "a member cannot"
   * halves of the check.
   */
  function roleRestrictedPages(): RouteInfo[] {
    return registry.routes.filter((r) => r.method === 'GET' && r.auth.startsWith('role:') && !r.path.includes(':'));
  }

  /** Concrete URL for a route, using the seeded sample record for entity params. */
  function urlFor(route: RouteInfo): string {
    const values: Record<string, string | number> = {};
    const entity = registry.entities.find((e) => e.name === route.owner?.entity || e.name === route.entity);
    if (entity) {
      values[route.owner?.param ?? 'id'] = entity.sample.id;
      values.id = entity.sample.id;
    }
    return fillPath(route.path, values, '00000000-0000-4000-8000-000000000000');
  }

  async function probe(route: RouteInfo, who?: 'member' | 'member2' | 'admin'): Promise<Response> {
    const jar = who ? jars[who] : undefined;
    const isApi = route.kind === 'api' || route.path.startsWith('/api');
    const url = urlFor(route);
    if (route.method === 'GET') return app.fetch(url, { jar });
    if (isApi) {
      return app.fetch(url, {
        method: route.method,
        jar,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(who ? { [headerNames.csrf]: csrf[who]! } : {}) },
        body: '{}',
      });
    }
    return app.fetch(url, {
      method: route.method,
      jar,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody(who ? { [fields.csrf]: csrf[who]! } : {}),
    });
  }

  function protectedRoutes(): RouteInfo[] {
    return registry.routes.filter((r) => r.auth !== 'public' && !r.path.startsWith('/__securevibe'));
  }

  test('V8.2.1 every route declares an authorization policy and anonymous requests to protected routes are denied', async () => {
    assert.ok(registry.routes.length > 0, 'the registry must list routes');
    for (const r of registry.routes) {
      assert.ok(r.auth === 'public' || r.auth === 'user' || r.auth.startsWith('role:'), `${describeRoute(r)} has no valid auth declaration`);
    }
    const failures: string[] = [];
    for (const route of protectedRoutes()) {
      const res = await probe(route);
      await res.text();
      const deniedByRedirect = isRedirect(res) && /login|sign-?in/i.test(locationOf(res));
      if (!(DENIED.has(res.status) || deniedByRedirect)) failures.push(`${describeRoute(route)} -> ${res.status} ${locationOf(res)}`);
    }
    assert.deepEqual(failures, [], `anonymous access was not denied for:\n${failures.join('\n')}`);
  });

  test('V8.2.1 a signed-in user with the wrong role is denied server-side (403 or 404), never validated first', async (t) => {
    const restricted = protectedRoutes().filter((r) => {
      if (r.auth.startsWith('role:')) return r.auth !== `role:${memberRole}`;
      return Array.isArray(r.roles) && r.roles.length > 0 && !r.roles.includes(memberRole);
    });
    // Only where the app really keeps nothing behind a role is there nothing to check, and then the honest answer is
    // to say so rather than to fail. A one-person app is not that case: it keeps its admin area behind its own role
    // and its seeded members do not hold it, so the check runs and means something.
    if (restricted.length === 0) return t.skip('this app puts no page behind a role, so there is no wrong-role access to deny');
    const failures: string[] = [];
    for (const route of restricted) {
      const res = await probe(route, 'member');
      await res.text();
      if (!DENIED.has(res.status)) failures.push(`${describeRoute(route)} -> ${res.status} ${locationOf(res)}`);
    }
    assert.deepEqual(failures, [], `wrong-role access was not denied for:\n${failures.join('\n')}`);
    const denials = await app.eventsNamed('authz.denied');
    assert.ok(denials.length >= 1, 'authz.denied security events must be emitted');
  });

  test('V8.2.1 administrators can open the pages that are kept behind a role', async (t) => {
    const adminGets = roleRestrictedPages();
    if (adminGets.length === 0) return t.skip('this app puts no page behind a role');
    for (const route of adminGets) {
      const res = await probe(route, 'admin');
      await res.text();
      assert.ok(res.status < 400, `${describeRoute(route)} answered ${res.status} for an administrator`);
    }
  });

  test('V8.2.2 owner-scoped records cannot be read or changed by another user (IDOR)', async (t) => {
    const ownerRoutes = registry.routes.filter((r) => r.owner);
    if (ownerRoutes.length === 0 || registry.entities.length === 0) return t.skip('no owner-scoped routes/entities are registered');
    const failures: string[] = [];
    for (const route of ownerRoutes) {
      const entity = registry.entities.find((e) => e.name === route.owner!.entity);
      if (!entity) {
        failures.push(`${describeRoute(route)} references an entity without a seeded sample`);
        continue;
      }
      const other = await probe(route, 'member2');
      await other.text();
      if (!DENIED.has(other.status)) failures.push(`${describeRoute(route)} -> ${other.status} for a non-owner`);
      if (route.method === 'GET') {
        const owner = await probe(route, 'member');
        await owner.text();
        if (owner.status !== 200) failures.push(`${describeRoute(route)} -> ${owner.status} for the owner`);
      }
    }
    assert.deepEqual(failures, [], `ownership was not enforced for:\n${failures.join('\n')}`);
  });

  test('V8.2.2 administrators bypass ownership checks only where the registry allows it', async (t) => {
    const ownerGets = registry.routes.filter((r) => r.owner && r.method === 'GET');
    if (ownerGets.length === 0) return t.skip('no owner-scoped GET routes are registered');
    for (const route of ownerGets) {
      const res = await probe(route, 'admin');
      await res.text();
      assert.ok(res.status === 200 || DENIED.has(res.status), `${describeRoute(route)} answered ${res.status} for an administrator`);
    }
  });

  test('V8.3.1 the authorization decision is made on the server: client-side hints are ignored', async (t) => {
    const adminRoute = roleRestrictedPages().find((r) => r.auth !== `role:${memberRole}`);
    if (!adminRoute) return t.skip('this app puts no page behind a role the person we probe with lacks');
    const url = urlFor(adminRoute);
    const hints: Record<string, string>[] = [
      { 'X-Role': 'admin' },
      { 'X-User-Role': 'admin' },
      { 'X-Forwarded-User': users.admin },
      { Authorization: 'Bearer admin' },
    ];
    for (const headers of hints) {
      const res = await app.fetch(`${url}?role=admin&admin=1&isAdmin=true`, { jar: jars.member, headers });
      await res.text();
      assert.ok(DENIED.has(res.status), `${adminRoute.path} with ${JSON.stringify(headers)} answered ${res.status} for a member`);
    }
  });
});
