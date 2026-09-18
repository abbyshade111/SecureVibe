/**
 * Security tests of the fixture app's route registry. Names start with the requirement id they evidence, the
 * way CONTRACTS §1.13 requires, so SecureVibe's test runner can turn them into evidence.
 */
import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import { ROUTES, findRoute, methodsForPath } from '../../src/routes.js';

test('V8.2.1 every route says who is allowed to use it', () => {
  for (const route of ROUTES) {
    assert.ok(route.auth === 'public' || route.auth === 'user' || route.auth.startsWith('role:'), `${route.method} ${route.path}`);
  }
});

test('V8.2.2 routes that read one record declare the owner check', () => {
  const byId = ROUTES.filter((r) => r.path.includes('/:id'));
  assert.ok(byId.length > 0);
  for (const route of byId) assert.equal(route.owner?.ownerField, 'owner_id', `${route.method} ${route.path}`);
});

describe('V13.4.4 method handling', () => {
  test('reports the methods a known path supports', () => {
    assert.deepEqual(methodsForPath('/login').sort(), ['GET', 'HEAD', 'POST']);
  });

  test('reports nothing for a path that does not exist', () => {
    assert.deepEqual(methodsForPath('/no-such-path'), []);
  });
});

test('V3.5.1 every state-changing route asks for a request token', () => {
  for (const route of ROUTES.filter((r) => r.method !== 'GET')) {
    assert.equal(route.csrf, true, `${route.method} ${route.path}`);
  }
});

test('finds a route by method and path', () => {
  assert.equal(findRoute('GET', '/notes/abc')?.path, '/notes/:id');
});
