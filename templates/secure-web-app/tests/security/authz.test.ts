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
    memberRole = registry.roles[registry.roles.length - 1] ?? 'member';
    for (const who of ['member', 'member2', 'admin'] as const) {
      jars[who] = await app.login(users[who]);
      csrf[who] = await app.csrfToken(paths.account, jars[who]);
    }
  });
  after(async () => {
    await app?.stop();
  });

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

  test('V8.2.1 a signed-in user with the wrong role is denied server-side (403 or 404), never validated first', async () => {
    const restricted = protectedRoutes().filter((r) => {
      if (r.auth.startsWith('role:')) return r.auth !== `role:${memberRole}`;
      return Array.isArray(r.roles) && r.roles.length > 0 && !r.roles.includes(memberRole);
    });
    assert.ok(restricted.length > 0, 'expected at least one role-restricted route (the admin area)');
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

  test('V8.2.1 administrators can open the admin pages that members cannot', async () => {
    const adminGets = registry.routes.filter((r) => r.method === 'GET' && r.auth === 'role:admin' && !r.path.includes(':'));
    assert.ok(adminGets.length > 0, 'expected admin GET routes');
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

  test('V8.3.1 the authorization decision is made on the server: client-side hints are ignored', async () => {
    const adminRoute = registry.routes.find((r) => r.method === 'GET' && r.auth === 'role:admin' && !r.path.includes(':'));
    assert.ok(adminRoute, 'expected an admin GET route');
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
