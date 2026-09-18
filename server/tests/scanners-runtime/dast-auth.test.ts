/**
 * How the probes sign in. The default follows the template's sign-in forms; SecureVibe's own self-assessment
 * plugs in the startup-token bootstrap through the same interface, so both are checked here.
 */
import type { RequestListener } from 'node:http';
import { describe, expect, it } from 'vitest';
import { formAuthBootstrap, startupTokenAuthBootstrap, type AuthBootstrapContext } from '../../src/scanners/dast/auth.js';
import { CookieJar } from '../../src/scanners/dast/http.js';
import type { AppInstance } from '../../src/scanners/dast/types.js';
import { LoopbackHttpClient } from './helpers/loopback.js';
import { startMiniApp, TEST_PASSWORD } from './helpers/mini-app.js';

const TOKEN = 'startup-token-6c2b1f90';

/** The smallest app that behaves like SecureVibe's own interface: a token exchanged for a session cookie. */
const tokenApp: RequestListener = (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  if (url.pathname === '/auth/token') {
    if (url.searchParams.get('token') !== TOKEN) {
      res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ error: { code: 'forbidden', message: 'That link is not valid.' } }));
      return;
    }
    res.writeHead(303, { Location: '/', 'Set-Cookie': 'sid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; HttpOnly; SameSite=Strict; Path=/' });
    res.end();
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end('<!doctype html><html><body><h1>SecureVibe</h1></body></html>');
};

function contextFor(client: LoopbackHttpClient): AuthBootstrapContext {
  return {
    http: client,
    app: { baseUrl: client.baseUrl } as AppInstance,
    routes: undefined,
    secrets: { password: TOKEN, totpSeed: '' },
    paths: { login: '/auth/token', loginMfa: '/auth/token', account: '/' },
    log: () => {},
  };
}

describe('the form sign-in bootstrap', () => {
  it('signs in a seeded account and completes the one-time code step for the administrator', async () => {
    const mini = await startMiniApp({ phase: 'test' });
    try {
      const ctx = contextFor(mini.client);
      const authCtx: AuthBootstrapContext = { ...ctx, routes: mini.ctx.routes, secrets: mini.ctx.secrets, paths: { login: '/login', loginMfa: '/login/mfa', account: '/account' } };
      const users = formAuthBootstrap.seededUsers(authCtx);
      expect(users.map((u) => u.label)).toEqual(['admin', 'staff', 'member', 'member2']);

      const admin = await formAuthBootstrap.login(users[0]!, authCtx);
      expect(admin?.role).toBe('admin');
      expect(admin?.jar.sessionId()?.length).toBeGreaterThanOrEqual(43);
      const page = await mini.client.get('/account', { jar: admin!.jar });
      expect(page.status).toBe(200);
      expect(page.body).toContain('admin@test.local');
    } finally {
      mini.close();
    }
  }, 60_000);

  it('says why an account could not be signed in instead of pretending it was', async () => {
    const mini = await startMiniApp({ phase: 'test' });
    const messages: string[] = [];
    try {
      const authCtx: AuthBootstrapContext = {
        http: mini.client,
        app: { baseUrl: mini.client.baseUrl } as AppInstance,
        routes: mini.ctx.routes,
        secrets: { password: 'not-the-password', totpSeed: mini.ctx.secrets.totpSeed },
        paths: { login: '/login', loginMfa: '/login/mfa', account: '/account' },
        log: (m) => messages.push(m),
      };
      const session = await formAuthBootstrap.login({ label: 'member', email: 'member@test.local', role: 'member', mfa: false }, authCtx);
      expect(session).toBeUndefined();
      expect(messages.join(' ')).toMatch(/could not sign in member@test\.local/);
    } finally {
      mini.close();
    }
  }, 60_000);

  it('sends the real password when asked to sign in for real', async () => {
    const mini = await startMiniApp({ phase: 'test' });
    try {
      expect(mini.env['SECUREVIBE_TEST_PASSWORD']).toBe(TEST_PASSWORD);
      const res = await mini.ctx.loginAttempt('member@test.local', mini.ctx.secrets.password);
      expect(res.isRedirect()).toBe(true);
    } finally {
      mini.close();
    }
  }, 60_000);
});

describe('the startup-token bootstrap', () => {
  it('exchanges the token for a session cookie', async () => {
    const client = new LoopbackHttpClient(tokenApp);
    try {
      const bootstrap = startupTokenAuthBootstrap({ token: TOKEN });
      const ctx = contextFor(client);
      const [user] = bootstrap.seededUsers(ctx);
      expect(user).toMatchObject({ label: 'owner', mfa: false });
      const session = await bootstrap.login(user!, ctx);
      expect(session?.jar.sessionId()).toBeTruthy();
    } finally {
      client.close();
    }
  });

  it('reports a refused token instead of returning a broken session', async () => {
    const client = new LoopbackHttpClient(tokenApp);
    const messages: string[] = [];
    try {
      const bootstrap = startupTokenAuthBootstrap({ token: 'the-wrong-token' });
      const ctx = { ...contextFor(client), log: (m: string) => messages.push(m) };
      const session = await bootstrap.login(bootstrap.seededUsers(ctx)[0]!, ctx);
      expect(session).toBeUndefined();
      expect(messages.join(' ')).toMatch(/startup token was not accepted/);
    } finally {
      client.close();
    }
  });

  it('can make a single attempt with a wrong token, the way the rate-limit probes do', async () => {
    const client = new LoopbackHttpClient(tokenApp);
    try {
      const bootstrap = startupTokenAuthBootstrap({ token: TOKEN });
      const res = await bootstrap.loginAttempt('owner@localhost', 'wrong', contextFor(client), new CookieJar(), { 'X-Forwarded-For': '203.0.113.7' });
      expect(res.status).toBe(403);
      expect(res.request.headers['X-Forwarded-For']).toBe('203.0.113.7');
    } finally {
      client.close();
    }
  });
});
