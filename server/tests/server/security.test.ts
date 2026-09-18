import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('local security posture', () => {
  let harness: TestHarness;

  beforeEach(async () => {
    harness = await buildHarness();
  });
  afterEach(() => harness?.cleanup());

  it('exchanges the startup token for a session cookie, once', async () => {
    const res = await request(harness.server).get(`/auth/token?t=${harness.sessions.startupToken}`).set('Host', '127.0.0.1');
    expect(res.status).toBe(303);
    const setCookie = res.headers['set-cookie'];
    expect(setCookie).toBeDefined();
    const cookie = Array.isArray(setCookie) ? setCookie[0]! : (setCookie as unknown as string);
    expect(cookie).toMatch(/securevibe_session=/);
    expect(cookie).toMatch(/HttpOnly/);
    expect(cookie).toMatch(/SameSite=Strict/);

    // The link keeps working for this process, so a prefetch or a reopened tab does not lock the owner out.
    const again = await request(harness.server).get(`/auth/token?t=${harness.sessions.startupToken}`).set('Host', '127.0.0.1');
    expect(again.status).toBe(303);
    expect(again.headers['set-cookie']?.[0]).toMatch(/HttpOnly/);
  });

  it('only signs in on 127.0.0.1, so a cookie a browser also sends to app previews on localhost is worthless', async () => {
    const onLocalhost = await request(harness.server).get(`/auth/token?t=${harness.sessions.startupToken}`).set('Host', 'localhost:4173');
    expect(onLocalhost.status).toBe(303);
    expect(onLocalhost.headers['location']).toBe(`http://127.0.0.1:4173/auth/token?t=${harness.sessions.startupToken}`);
    expect(onLocalhost.headers['set-cookie']).toBeUndefined();

    const res = await request(harness.server).get(`/auth/token?t=${harness.sessions.startupToken}`).set('Host', '127.0.0.1');
    const cookie = (res.headers['set-cookie'] as unknown as string[])[0]!.split(';')[0]!;
    expect((await request(harness.server).get('/api/projects').set('Host', '127.0.0.1').set('Cookie', cookie)).status).toBe(200);
    expect((await request(harness.server).get('/api/projects').set('Host', 'localhost').set('Cookie', cookie)).status).toBe(401);
    const page = await request(harness.server).get('/settings').set('Host', 'localhost:4173').set('Cookie', cookie);
    expect(page.status).toBe(302);
    expect(page.headers['location']).toBe('http://127.0.0.1:4173/settings');
  });

  it('rejects a wrong token', async () => {
    const res = await request(harness.server).get('/auth/token?t=not-the-real-token').set('Host', '127.0.0.1');
    expect(res.status).toBeGreaterThanOrEqual(400);
  });

  it('limits repeated wrong tokens, without counting successful exchanges', async () => {
    for (let i = 0; i < 12; i++) {
      await request(harness.server).get(`/auth/token?t=${harness.sessions.startupToken}`).set('Host', '127.0.0.1');
    }
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) {
      const res = await request(harness.server).get(`/auth/token?t=wrong-${i}`).set('Host', '127.0.0.1');
      statuses.push(res.status);
    }
    expect(statuses.slice(0, 10).every((s) => s === 403)).toBe(true);
    expect(statuses[10]).toBe(429);
  });

  it('answers unknown non-GET paths with a plain 404, not the framework default page', async () => {
    const res = await request(harness.server).post('/login').set('Host', '127.0.0.1').set('Content-Type', 'application/json').send('{}');
    expect(res.status).toBe(404);
    expect(res.text).toBe('Not found.');
    expect(res.text).not.toMatch(/Cannot POST|Express/);
  });

  it('serves a plain explanation page instead of the SPA when there is no session', async () => {
    const res = await request(harness.server).get('/').set('Host', '127.0.0.1');
    expect(res.status).toBe(401);
    expect(res.text).toMatch(/restart|link/i);
  });

  it('requires a session for /api routes', async () => {
    const res = await request(harness.server).get('/api/status').set('Host', '127.0.0.1');
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('unauthorized');
  });

  it('rejects requests addressed to a host other than 127.0.0.1/localhost', async () => {
    const res = await request(harness.server).get('/healthz').set('Host', 'evil.example.com');
    expect(res.status).toBe(421);
  });

  it('answers /healthz without a session', async () => {
    const res = await request(harness.server).get('/healthz').set('Host', '127.0.0.1');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  it('rejects a mutating request with a cross-site Origin, even with a valid session', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const res = await request(harness.server)
      .put('/api/settings')
      .set('Host', '127.0.0.1')
      .set('Cookie', cookie)
      .set('X-CSRF-Token', csrfToken)
      .set('Origin', 'https://evil.example.com')
      .send({ model: 'claude-opus-5' });
    expect(res.status).toBe(403);
  });

  it('rejects a mutating request without the CSRF token', async () => {
    const { cookie } = await signIn(harness);
    const res = await request(harness.server).put('/api/settings').set('Host', '127.0.0.1').set('Cookie', cookie).send({ model: 'claude-opus-5' });
    expect(res.status).toBe(403);
  });

  it('accepts a same-origin mutating request with a valid CSRF token', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const res = await request(harness.server)
      .put('/api/settings')
      .set('Host', '127.0.0.1')
      .set('Cookie', cookie)
      .set('X-CSRF-Token', csrfToken)
      .send({ maxFixRounds: 1 });
    expect(res.status).toBe(200);
    expect(res.body.settings.maxFixRounds).toBe(1);
  });

  it('sends a nonce-based CSP with no unsafe-inline', async () => {
    const { cookie } = await signIn(harness);
    const res = await request(harness.server).get('/healthz').set('Host', '127.0.0.1').set('Cookie', cookie);
    const csp = res.headers['content-security-policy'];
    expect(csp).toBeDefined();
    expect(csp).toMatch(/script-src 'nonce-[^']+' 'strict-dynamic'/);
    expect(csp).not.toMatch(/unsafe-inline/);
    expect(csp).toMatch(/object-src 'none'/);
    expect(csp).toMatch(/frame-ancestors 'none'/);
  });

  it('marks signed-in responses as not cacheable', async () => {
    const { cookie } = await signIn(harness);
    const res = await request(harness.server).get('/api/status').set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('requires the CSRF token to sign out', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const without = await request(harness.server).post('/auth/logout').set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(without.status).toBe(403);
    const still = await request(harness.server).get('/api/status').set('Host', '127.0.0.1').set('Cookie', cookie);
    expect(still.status).toBe(200);
    const signedOut = await request(harness.server).post('/auth/logout').set('Host', '127.0.0.1').set('Cookie', cookie).set('X-CSRF-Token', csrfToken);
    expect(signedOut.status).toBe(204);
    expect(signedOut.headers['clear-site-data']).toBe('"cookies", "storage"');
  });

  it('answers 404, not 500, for malformed or path-like project ids', async () => {
    const { cookie } = await signIn(harness);
    for (const id of ["'", '..%2F..%2F.env', 'p_zzzzzzzzzz']) {
      const res = await request(harness.server).get(`/api/projects/${id}/estimate`).set('Host', '127.0.0.1').set('Cookie', cookie);
      expect(res.status, id).toBe(404);
    }
  });
});
