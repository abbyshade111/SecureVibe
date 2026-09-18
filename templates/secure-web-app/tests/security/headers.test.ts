/** Security headers (contract §1.5): CSP with per-request nonce, hardening headers, cache control, health endpoints. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { CookieJar, startApp, type RunningApp } from '../helpers/app.ts';
import { paths, users } from '../helpers/conventions.ts';

/** Sends one request over a plain socket, for methods Node's fetch refuses to send (TRACE). */
function rawRequest(port: number, method: string, path: string, timeoutMs = 10_000): Promise<{ status: number; statusLine: string; raw: string }> {
  return new Promise((resolve, reject) => {
    let raw = '';
    const socket = connect(port, '127.0.0.1', () => {
      socket.write(`${method} ${path} HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\nConnection: close\r\n\r\n`);
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`${method} ${path} did not answer within ${timeoutMs} ms`));
    });
    socket.on('data', (chunk: Buffer) => {
      raw += chunk.toString('latin1');
    });
    socket.on('error', reject);
    socket.on('close', () => {
      const statusLine = raw.split('\r\n')[0] ?? '';
      resolve({ status: Number(statusLine.match(/^HTTP\/\d\.\d (\d{3})/)?.[1] ?? 0), statusLine, raw });
    });
  });
}

/** Splits a CSP header into a map of directive -> sorted source list. */
function parseCsp(value: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of value.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const [name, ...sources] = tokens;
    out.set(name!.toLowerCase(), sources.sort());
  }
  return out;
}

const EXPECTED_CSP: Record<string, (nonce: string) => string[]> = {
  'default-src': () => ["'self'"],
  'script-src': (n) => [`'nonce-${n}'`, "'strict-dynamic'"].sort(),
  'style-src': (n) => ["'self'", `'nonce-${n}'`].sort(),
  'img-src': () => ["'self'", 'data:'].sort(),
  'font-src': () => ["'self'"],
  'connect-src': () => ["'self'"],
  'object-src': () => ["'none'"],
  'base-uri': () => ["'none'"],
  'frame-ancestors': () => ["'none'"],
  'form-action': () => ["'self'"],
};

describe('headers', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  test('V3.4.3 every page carries the exact nonce-based Content-Security-Policy', async () => {
    const first = await app.fetch(paths.login);
    const firstHtml = await first.text();
    const csp = first.headers.get('content-security-policy');
    assert.ok(csp, 'Content-Security-Policy header missing');
    const nonceMatch = csp.match(/'nonce-([^']+)'/);
    assert.ok(nonceMatch, `CSP has no nonce: ${csp}`);
    const nonce = nonceMatch[1]!;
    assert.ok(Buffer.from(nonce, 'base64').length >= 16, 'nonce must be at least 128 bits');

    const directives = parseCsp(csp);
    for (const [name, expected] of Object.entries(EXPECTED_CSP)) {
      assert.deepEqual(directives.get(name), expected(nonce), `CSP directive ${name} differs: ${csp}`);
    }
    // Plain HTTP on loopback: upgrade-insecure-requests only appears in TLS modes.
    assert.equal(directives.has('upgrade-insecure-requests'), false, 'upgrade-insecure-requests must only be set in TLS modes');
    const unexpected = [...directives.keys()].filter((k) => !(k in EXPECTED_CSP));
    assert.deepEqual(unexpected, [], `unexpected CSP directives: ${unexpected.join(', ')}`);

    // Inline scripts on the page must carry the same nonce, and none may be unnonced.
    for (const m of firstHtml.matchAll(/<script\b([^>]*)>/gi)) {
      // The nonce is base64, so it may contain + and / and must be escaped before it goes into a pattern.
      const escaped = nonce.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
      assert.match(m[1] ?? '', new RegExp(`nonce=["']${escaped}["']`), `a <script> tag without the response nonce: <script${m[1]}>`);
    }

    const second = await app.fetch(paths.login);
    await second.text();
    const secondNonce = second.headers.get('content-security-policy')?.match(/'nonce-([^']+)'/)?.[1];
    assert.ok(secondNonce, 'second response has no nonce');
    assert.notEqual(secondNonce, nonce, 'nonce must change on every request');
  });

  test('V3.4.4 hardening headers: nosniff, Referrer-Policy, Permissions-Policy, frame denial', async () => {
    const res = await app.fetch(paths.login);
    await res.text();
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(res.headers.get('referrer-policy'), 'strict-origin-when-cross-origin');
    const pp = res.headers.get('permissions-policy') ?? '';
    for (const feature of ['camera=()', 'microphone=()', 'geolocation=()']) assert.ok(pp.includes(feature), `Permissions-Policy lacks ${feature}: ${pp}`);
    assert.equal(res.headers.get('x-frame-options'), 'DENY');
    assert.equal(res.headers.get('x-powered-by'), null, 'X-Powered-By must not be sent');
  });

  test('V3.4.5 Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy isolate the app', async () => {
    const res = await app.fetch(paths.login);
    await res.text();
    assert.equal(res.headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(res.headers.get('cross-origin-resource-policy'), 'same-origin');
  });

  test('V4.1.1 every response with a body declares a Content-Type with charset=utf-8', async () => {
    const checks: [string, RegExp][] = [
      [paths.login, /^text\/html;\s*charset=utf-8$/i],
      [paths.healthz, /^application\/json;\s*charset=utf-8$/i],
      ['/this-page-does-not-exist', /charset=utf-8/i],
      ['/api/this-route-does-not-exist', /^application\/json;\s*charset=utf-8$/i],
    ];
    for (const [path, expected] of checks) {
      const res = await app.fetch(path);
      const body = await res.text();
      assert.ok(body.length > 0, `${path} returned an empty body`);
      assert.match(res.headers.get('content-type') ?? '', expected, `Content-Type of ${path}`);
    }
  });

  test('V3.4.2 no CORS: a foreign Origin is never reflected and preflights are not answered', async () => {
    const res = await app.fetch(paths.login, { headers: { Origin: 'https://evil.example' } });
    await res.text();
    assert.equal(res.headers.get('access-control-allow-origin'), null);
    assert.equal(res.headers.get('access-control-allow-credentials'), null);

    const preflight = await app.fetch(paths.login, {
      method: 'OPTIONS',
      sameOrigin: false,
      headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'POST' },
    });
    await preflight.text();
    assert.equal(preflight.headers.get('access-control-allow-origin'), null, 'preflight must not grant cross-origin access');
  });

  test('V14.3.2 authenticated responses are marked Cache-Control: no-store, private', async () => {
    const jar = await app.login(users.member);
    const res = await app.fetch(paths.account, { jar });
    await res.text();
    assert.equal(res.status, 200);
    const cc = (res.headers.get('cache-control') ?? '').toLowerCase();
    assert.ok(cc.includes('no-store'), `Cache-Control on an authenticated page must contain no-store: "${cc}"`);
    assert.ok(cc.includes('private'), `Cache-Control on an authenticated page must contain private: "${cc}"`);
  });

  test('V14.3.1 logout sends Clear-Site-Data for cookies and storage', async () => {
    const jar = await app.login(users.member);
    const res = await app.logout(jar);
    await res.text();
    const csd = res.headers.get('clear-site-data') ?? '';
    assert.ok(csd.includes('"cookies"'), `Clear-Site-Data must include "cookies": "${csd}"`);
    assert.ok(csd.includes('"storage"'), `Clear-Site-Data must include "storage": "${csd}"`);
  });

  test('V13.4.4 TRACE is not supported', async () => {
    // Node's fetch refuses to send TRACE ("'TRACE' HTTP method is unsupported"), so the probe is a raw request.
    const response = await rawRequest(app.port, 'TRACE', paths.home);
    assert.equal(response.status, 405, `TRACE ${paths.home} answered: ${response.statusLine}`);
  });

  test('V13.4.1 dotfiles, .git and .env are never served and directories are not listed', async () => {
    for (const path of ['/.env', '/.env.example', '/.git/config', '/.git/HEAD', '/.npmrc', '/package.json', '/package-lock.json', '/src/config.ts']) {
      const res = await app.fetch(path);
      const body = await res.text();
      assert.ok([403, 404].includes(res.status), `${path} answered ${res.status}`);
      assert.ok(!body.includes('SESSION_SECRET'), `${path} leaked configuration`);
    }
    for (const dir of ['/css/', '/js/', '/public/', '/uploads/']) {
      const res = await app.fetch(dir);
      const body = await res.text();
      assert.ok(!/index of|directory listing/i.test(body), `${dir} looks like a directory listing`);
      assert.ok(res.status !== 200 || !/<a href="[^"]+\.(css|js)"/i.test(body), `${dir} lists files`);
    }
  });

  test('V13.4.5 health endpoint returns only a minimal status object', async () => {
    const res = await app.fetch(paths.healthz);
    const body = await res.text();
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(body), { status: 'ok' });
    const ready = await app.fetch(paths.readyz);
    const readyBody = await ready.text();
    assert.ok([200, 503].includes(ready.status), `/readyz answered ${ready.status}`);
    const parsed = JSON.parse(readyBody) as Record<string, unknown>;
    assert.deepEqual(Object.keys(parsed), ['status'], `/readyz must expose only a status field: ${readyBody}`);
  });

  test('V3.3.2 session cookie is HttpOnly, SameSite=Strict, Path=/ and the id appears nowhere else', async () => {
    const jar = new CookieJar();
    const res = await app.loginRaw(users.member, app.password, jar);
    const text = await res.text();
    const setCookie = res.headers.getSetCookie().find((c) => /^(__Host-)?sid=/.test(c));
    assert.ok(setCookie, `login did not set a session cookie: ${res.headers.getSetCookie().join(' | ')}`);
    const attrs = setCookie.toLowerCase();
    assert.ok(attrs.includes('httponly'), `session cookie is not HttpOnly: ${setCookie}`);
    assert.ok(attrs.includes('samesite=strict'), `session cookie is not SameSite=Strict: ${setCookie}`);
    assert.ok(/path=\/(;|$)/.test(attrs), `session cookie Path must be /: ${setCookie}`);
    const sid = jar.sessionId()!;
    assert.ok(!(res.headers.get('location') ?? '').includes(sid), 'session id must not be in the redirect URL');
    assert.ok(!text.includes(sid), 'session id must not be in the response body');
  });
});
