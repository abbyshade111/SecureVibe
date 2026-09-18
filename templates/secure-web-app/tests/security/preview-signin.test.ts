/**
 * SecureVibe's app preview signs a visitor in through a one-time link (PREVIEW_SIGNIN_TOKEN) so trying the app out
 * needs no password. Everything here checks that the shortcut exists only in a preview: without the value, or with
 * a wrong one, the link behaves like a wrong password. config.previewMode additionally requires plain http and a
 * loopback-only app, which is covered by the config tests.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, startApp, type RunningApp } from '../helpers/app.ts';

const TOKEN = 'preview-signin-token-that-is-long-enough-000000';

describe('preview sign-in', () => {
  let plain: RunningApp;
  let preview: RunningApp;

  before(async () => {
    plain = await startApp();
    preview = await startApp({ env: { PREVIEW_SIGNIN_TOKEN: TOKEN } });
  });
  after(async () => {
    await plain?.stop();
    await preview?.stop();
  });

  test('V7.1.1 without PREVIEW_SIGNIN_TOKEN the link never signs anybody in', async () => {
    const jar = new CookieJar();
    const res = await plain.fetch(`/preview-signin?t=${TOKEN}`, { jar, redirect: 'manual' });
    assert.equal(res.status, 400);
    // An anonymous session cookie is ordinary; what matters is that nobody is signed in by it.
    const { html } = await plain.page('/', jar);
    assert.ok(html.includes('Please sign in to continue'), 'the link signed somebody in on an ordinary app');
    assert.ok(!html.includes('Preview:'), 'an ordinary app shows no preview notice');
  });

  test('V7.1.1 in a preview the link signs in as the administrator and every page says so', async () => {
    const jar = new CookieJar();
    const res = await preview.fetch(`/preview-signin?t=${TOKEN}`, { jar, redirect: 'manual' });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/');
    const { res: home, html } = await preview.page('/', jar);
    assert.equal(home.status, 200);
    assert.ok(html.includes('Preview:'), 'the preview notice is on the page');
    // Signed in without a password, and without the "choose a new password" step.
    assert.ok(!html.includes('Please sign in to continue'), `home page still asks for sign-in:\n${html.slice(0, 400)}`);
  });

  test('V7.1.1 a wrong or missing value is refused like a wrong password, and leaves no session', async () => {
    for (const query of ['', '?t=', `?t=${'x'.repeat(TOKEN.length)}`]) {
      const jar = new CookieJar();
      const res = await preview.fetch(`/preview-signin${query}`, { jar, redirect: 'manual' });
      assert.ok(res.status === 400, `${query || '(no query)'} gave ${res.status}`);
      const { html } = await preview.page('/', jar);
      assert.ok(html.includes('Please sign in to continue'), `${query || '(no query)'} left a session behind`);
    }
  });
});
