/** Safe redirects (TPL-REDIRECT-01, contract §1.2 safeRedirect): only allow-listed local paths. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, paths, users } from '../helpers/conventions.ts';

const EVIL = [
  'https://evil.example/phish',
  'http://evil.example',
  '//evil.example/path',
  '/\\evil.example',
  '\\/evil.example',
  'https:evil.example',
  'javascript:alert(1)',
  '/%2F%2Fevil.example',
  '/\t/evil.example',
  'http://127.0.0.1@evil.example/',
  '///evil.example',
  '/account\r\nSet-Cookie: x=y',
];

function isLocal(location: string, origin: string): boolean {
  if (location === '') return true;
  if (location.startsWith(origin + '/')) return true;
  if (location === origin) return true;
  return /^\/(?![/\\])/.test(location) && !/[\r\n]/.test(location) && !/^\/\\/.test(location);
}

describe('redirect', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  test('V3.7.2 the login return-to parameter never redirects to another host or scheme', async () => {
    for (const target of EVIL) {
      const jar = new CookieJar();
      const loginPage = `${paths.login}?${fields.next}=${encodeURIComponent(target)}`;
      const page = await app.fetch(loginPage, { jar });
      const html = await page.text();
      assert.ok(page.status < 400 || page.status === 400, `login page with next=${target} answered ${page.status}`);
      if (page.status === 400) continue;
      for (const m of html.matchAll(/(?:href|action)=["']([^"']+)["']/g)) {
        assert.ok(!/evil\.example/.test(m[1]!) || m[1]!.startsWith(`${paths.login}?`), `the page links to the attacker host: ${m[1]}`);
      }
      const res = await app.submitForm(paths.login, { [fields.email]: users.member, [fields.password]: app.password, [fields.next]: target }, jar, { csrfFrom: loginPage });
      await res.text();
      const location = locationOf(res);
      assert.ok(isLocal(location, app.origin()), `next=${JSON.stringify(target)} redirected to ${JSON.stringify(location)}`);
      assert.ok(!/evil\.example/.test(location), `redirect target leaked the attacker host: ${location}`);
    }
  });

  test('V3.7.2 a valid local return-to path is honoured or ignored, never rewritten to something else', async () => {
    const jar = new CookieJar();
    const loginPage = `${paths.login}?${fields.next}=${encodeURIComponent(paths.sessions)}`;
    const res = await app.submitForm(paths.login, { [fields.email]: users.member, [fields.password]: app.password, [fields.next]: paths.sessions }, jar, { csrfFrom: loginPage });
    await res.text();
    assert.ok(isRedirect(res));
    const location = locationOf(res);
    assert.ok(isLocal(location, app.origin()), `unexpected redirect ${location}`);
    assert.equal(await app.isAuthenticated(jar), true);
  });

  test('V3.7.2 logout and other redirects ignore attacker-controlled targets in the query string and Referer', async () => {
    const jar = await app.login(users.member);
    const res = await app.submitForm(`${paths.logout}?${fields.next}=https://evil.example/`, { [fields.next]: '//evil.example' }, jar, {
      csrfFrom: paths.account,
      headers: { Referer: 'https://evil.example/' },
    });
    await res.text();
    const location = locationOf(res);
    assert.ok(isLocal(location, app.origin()), `logout redirected to ${location}`);
    const referer = await app.fetch(paths.account, { headers: { Referer: 'https://evil.example/' } });
    await referer.text();
    assert.ok(isLocal(locationOf(referer), app.origin()), `anonymous access redirected to ${locationOf(referer)}`);
  });

  test('V1.2.2 the Location header is a single well-formed value (no header injection through redirect targets)', async () => {
    const jar = new CookieJar();
    const target = '/account%0d%0aSet-Cookie:%20evil=1';
    const res = await app.submitForm(paths.login, { [fields.email]: users.member, [fields.password]: app.password, [fields.next]: target }, jar, { csrfFrom: paths.login });
    await res.text();
    const cookies = res.headers.getSetCookie();
    assert.ok(!cookies.some((c) => c.startsWith('evil=')), 'a redirect target must not inject headers');
    assert.doesNotMatch(locationOf(res), /[\r\n]/);
  });
});
