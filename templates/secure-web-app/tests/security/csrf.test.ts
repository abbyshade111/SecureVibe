/** CSRF protection (contract §1.4 csrf, TPL-CSRF-01): synchronizer token, Origin / Sec-Fetch-Site checks, no GET mutations. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { formBody, startApp, type RunningApp } from '../helpers/app.ts';
import { exampleNote, fields, paths, users } from '../helpers/conventions.ts';

describe('csrf', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  test('V3.5.1 a state-changing form post without the synchronizer token is rejected and changes nothing', async () => {
    const jar = await app.login(users.member);
    const since = new Date().toISOString();
    const res = await app.submitForm(paths.logout, {}, jar, { csrfToken: null });
    await res.text();
    assert.equal(res.status, 403, 'POST without CSRF token must be rejected with 403');
    assert.equal(await app.isAuthenticated(jar), true, 'the session must be untouched when the token is missing');

    const bogus = await app.submitForm(paths.logout, {}, jar, { csrfToken: 'not-a-valid-token' });
    await bogus.text();
    assert.equal(bogus.status, 403, 'POST with a wrong CSRF token must be rejected with 403');
    assert.equal(await app.isAuthenticated(jar), true);

    const events = await app.waitForEvent('csrf.rejected', since);
    assert.ok(events.length >= 1, 'csrf.rejected security event must be emitted');
  });

  test('V3.5.1 a valid token sent from a foreign Origin or a cross-site fetch is rejected', async () => {
    const jar = await app.login(users.member);
    const token = await app.csrfToken(paths.account, jar);

    const foreignOrigin = await app.submitForm(paths.logout, {}, jar, {
      csrfToken: token,
      headers: { Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' },
    });
    await foreignOrigin.text();
    assert.equal(foreignOrigin.status, 403, 'foreign Origin must be rejected');
    assert.equal(await app.isAuthenticated(jar), true);

    const crossSite = await app.submitForm(paths.logout, {}, jar, {
      csrfToken: token,
      headers: { Origin: app.origin(), 'Sec-Fetch-Site': 'cross-site' },
    });
    await crossSite.text();
    assert.equal(crossSite.status, 403, 'Sec-Fetch-Site: cross-site must be rejected');
    assert.equal(await app.isAuthenticated(jar), true);
  });

  test('V3.5.1 JSON API mutations require the CSRF header for session-authenticated callers', async (t) => {
    if (!(await app.featureEnabled('example'))) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const jar = await app.login(users.member);
    const res = await app.json('POST', paths.notesApi, exampleNote, jar, { csrfToken: null });
    await res.text();
    assert.equal(res.status, 403, 'JSON POST without the CSRF header must be rejected');

    const ok = await app.json('POST', paths.notesApi, exampleNote, jar);
    const body = await ok.text();
    assert.ok([200, 201].includes(ok.status), `JSON POST with the CSRF header failed: ${ok.status} ${body.slice(0, 200)}`);
  });

  test('V3.5.2 protection does not rely on CORS preflight: a cross-origin request that triggers no preflight is refused, and no CORS access is ever granted', async () => {
    // Forms and text/plain posts are "simple" requests: a browser sends them cross-origin without asking first, so a
    // defence that only works when the browser preflights would not stop them. Here each one carries a valid token
    // and the victim's cookie and is still refused on its own merits (Origin and Fetch Metadata), and the app never
    // answers with a CORS grant that would make a preflight the thing standing in the way.
    const simpleTypes = ['application/x-www-form-urlencoded', 'text/plain', 'multipart/form-data; boundary=x'];
    for (const type of simpleTypes) {
      const jar = await app.login(users.member);
      const token = await app.csrfToken(paths.account, jar);
      const res = await app.fetch(paths.logout, {
        method: 'POST',
        jar,
        sameOrigin: false,
        headers: { 'Content-Type': type, Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' },
        body: `${fields.csrf}=${encodeURIComponent(token)}`,
      });
      await res.text();
      assert.equal(res.status, 403, `a cross-origin ${type} request must be refused without any preflight`);
      assert.equal(res.headers.get('access-control-allow-origin'), null, 'no CORS grant may be sent on the refusal');
      assert.equal(await app.isAuthenticated(jar), true, 'the refused request must not have acted');
    }
    const preflight = await app.fetch(paths.logout, {
      method: 'OPTIONS',
      sameOrigin: false,
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'content-type' },
    });
    await preflight.text();
    for (const h of ['access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers', 'access-control-allow-credentials']) {
      assert.equal(preflight.headers.get(h), null, `a preflight must not be answered with ${h}: the app grants no cross-origin access`);
    }
  });

  test('V3.5.3 GET requests never change state (logout via GET keeps the session)', async () => {
    const jar = await app.login(users.member);
    const res = await app.fetch(paths.logout, { jar });
    await res.text();
    assert.equal(await app.isAuthenticated(jar), true, 'a GET to the logout path must not end the session');
    const withQuery = await app.fetch(`${paths.logout}?${fields.csrf}=${encodeURIComponent(await app.csrfToken(paths.account, jar))}`, { jar });
    await withQuery.text();
    assert.equal(await app.isAuthenticated(jar), true, 'a GET with the token in the query string must not end the session');
  });

  test('V3.5.1 the token is bound to the session: a token from another session is rejected', async () => {
    const alice = await app.login(users.member);
    const bob = await app.login(users.member2);
    const bobToken = await app.csrfToken(paths.account, bob);
    const res = await app.fetch(paths.logout, {
      method: 'POST',
      jar: alice,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody({ [fields.csrf]: bobToken }),
    });
    await res.text();
    assert.equal(res.status, 403, "another user's token must not be accepted");
    assert.equal(await app.isAuthenticated(alice), true);
  });
});
