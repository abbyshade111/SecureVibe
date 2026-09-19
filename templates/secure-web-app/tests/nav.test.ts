/**
 * The menu (src/lib/nav.ts).
 *
 * Deliberately no requirement id on these test names, and so deliberately not in tests/security/. The menu decides
 * where a link appears, not who may follow it: every page is guarded by its own route's `auth` and `roles` whether
 * or not it is in the menu, and those guards are what tests/security/authz.test.ts covers. A test named after an
 * access-control requirement here would credit that requirement with evidence from a list of links, which is the
 * mistake SecureVibe's misnamed-test screen exists to catch.
 *
 * What is worth testing is that the menu does not *offer* a page to somebody who would then be refused it — an
 * invitation to a locked door is a small dishonesty of its own — and that a page which asks for a place in the menu
 * gets one, because before that mechanism existed a page spanning several record types was reachable from nowhere.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import type { SessionUser } from '../src/features/auth/repo.ts';

/**
 * This is the only test in the suite that loads the app's own modules into the test process rather than starting the
 * app as a child, because the menu is a plain function over the route registry and there is nothing to serve. Loading
 * them means the configuration must be valid first, so it is filled in here with values generated on the spot. They
 * are throwaway: this process opens no port, writes no database and serves nothing, so nothing is protected by them.
 */
const b64 = (n: number): string => randomBytes(n).toString('base64');
process.env['NODE_ENV'] ??= 'test';
// Set rather than defaulted, and set to this value on purpose: `silent` is what SecureVibe's test runner passes when
// it runs a built app's suite, and the app's configuration used to reject it, so every app it built reported this
// file as a failing test while the template's own suite passed. Asking for it here keeps the two honest.
process.env['LOG_LEVEL'] = 'silent';
process.env['SESSION_SECRET'] ??= b64(32);
process.env['FIELD_KEYS'] ??= `1:${b64(32)}`;
process.env['ACTIVE_FIELD_KEY'] ??= '1';
process.env['TOKEN_HMAC_KEY'] ??= b64(32);

// Imported after the configuration above, which is why these are not at the top with the rest.
const { defineRoute } = await import('../src/security/routes.ts');
const { navItems } = await import('../src/lib/nav.ts');

const member = { id: 'u_member', email: 'member@example.test', role: 'member', isAdmin: false } as unknown as SessionUser;
const admin = { id: 'u_admin', email: 'admin@example.test', role: 'admin', isAdmin: true } as unknown as SessionUser;

/** Registers the routes these tests are about. The registry is module-level, and each test file is its own process. */
function register(): void {
  const router = Router();
  const noop = (): void => {};
  // A record type's own list page, and two of its inner pages that must not each become a menu item.
  defineRoute(router, { method: 'GET', path: '/widgets', auth: 'user', entity: 'widget', kind: 'page', summary: 'Widgets' }, noop);
  defineRoute(router, { method: 'GET', path: '/widgets/new', auth: 'user', entity: 'widget', kind: 'page' }, noop);
  defineRoute(router, { method: 'GET', path: '/widgets/:id', auth: 'user', entity: 'widget', kind: 'page', schema: { params: z.strictObject({ id: z.string() }) } }, noop);
  // A page below the top level that asks for a place in the menu, the way the chart recipe's pages do.
  defineRoute(router, { method: 'GET', path: '/charts/widgets', auth: 'user', entity: 'widget', kind: 'page', menu: 'Widgets over time' }, noop);
  // A page that spans record types and so has no entity at all.
  defineRoute(router, { method: 'GET', path: '/coming-up', auth: 'user', kind: 'page', menu: 'Coming up' }, noop);
  // A menu page only administrators may open.
  defineRoute(router, { method: 'GET', path: '/audit', auth: 'role:admin', kind: 'page', menu: 'Audit' }, noop);
  // A public page, and a JSON route: neither belongs in a signed-in person's menu.
  defineRoute(router, { method: 'GET', path: '/prices', auth: 'public', entity: 'price', kind: 'page', menu: 'Prices' }, noop);
  defineRoute(router, { method: 'GET', path: '/api/widgets', auth: 'user', entity: 'widget', kind: 'api', menu: 'Widgets data' }, noop);
}

describe('the menu', () => {
  register();

  test('offers nothing at all to somebody who has not signed in', () => {
    assert.deepEqual(navItems(null), []);
  });

  test('offers a record type once, by its list page and not its inner pages', () => {
    const hrefs = navItems(member).map((i) => i.href);
    assert.ok(hrefs.includes('/widgets'), 'the list page must be offered');
    assert.ok(!hrefs.includes('/widgets/new'), 'an inner page must not be offered');
    assert.ok(!hrefs.includes('/widgets/:id'), 'a page with a parameter must not be offered');
  });

  test('offers a page that asked for the menu, under the label it asked for, wherever it sits', () => {
    const items = navItems(member);
    const chart = items.find((i) => i.href === '/charts/widgets');
    assert.ok(chart, 'a page below the top level that asked for the menu must be offered');
    assert.equal(chart!.label, 'Widgets over time', 'the label is the one the page gave');
    const across = items.find((i) => i.href === '/coming-up');
    assert.ok(across, 'a page with no record type of its own must still be offered when it asks');
    assert.equal(across!.label, 'Coming up');
    // Asking for the menu does not displace the record type's own list page, nor cost it its place.
    assert.ok(items.some((i) => i.href === '/widgets'), 'the record type is still offered alongside its chart');
  });

  test('never offers a page the person would then be refused', () => {
    const forMember = navItems(member).map((i) => i.href);
    assert.ok(!forMember.includes('/audit'), 'a page only administrators may open must not be offered to anybody else');
    assert.ok(navItems(admin).some((i) => i.href === '/audit'), 'an administrator is offered it');
  });

  test('leaves out pages that are nobody\u2019s business in a menu: public pages and data routes', () => {
    const hrefs = navItems(member).map((i) => i.href);
    assert.ok(!hrefs.includes('/prices'), 'a public page is linked by the layout, not the menu');
    assert.ok(!hrefs.includes('/api/widgets'), 'a data route is not a page');
  });
});
