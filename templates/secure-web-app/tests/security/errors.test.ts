/** Error handling and resilience (TPL-ERRORS-01, TPL-RESILIENCE-01, RR-06). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { connect } from 'node:net';
import { startApp, type RunningApp } from '../helpers/app.ts';
import { paths, users } from '../helpers/conventions.ts';

const INTERNALS = /at\s+\S+\s+\(?.*\.(ts|js):\d+|node_modules|node:internal|Error:|SQLITE|sqlite_|ZodError|TypeError|ReferenceError|ENOENT|EACCES|stack/i;

describe('errors', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  test('V16.5.1 unknown pages and API paths return generic messages without stack traces or internals', async () => {
    const page = await app.fetch('/definitely/not/a/page');
    const pageText = await page.text();
    assert.equal(page.status, 404);
    assert.doesNotMatch(pageText, INTERNALS, 'the 404 page leaks internals');
    assert.doesNotMatch(pageText, /\/Users\/|\/home\/|C:\\/, 'the 404 page leaks file system paths');

    const api = await app.fetch('/api/definitely/not/a/route');
    const apiText = await api.text();
    assert.equal(api.status, 404);
    assert.match(api.headers.get('content-type') ?? '', /application\/json/);
    const body = JSON.parse(apiText) as { error?: { code?: string; message?: string } };
    assert.ok(body.error?.code, 'API 404 must use the uniform error model {error:{code,message}}');
    assert.doesNotMatch(apiText, INTERNALS, 'the API 404 leaks internals');
  });

  test('V16.5.1 malformed input never produces a 500 and errors are the uniform error model', async () => {
    const attempts: [string, RequestInit & { headers?: Record<string, string> }][] = [
      [paths.login, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"broken":' }],
      [paths.login, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: '%E0%A4%A=1&=&&' }],
      [`${paths.login}?%FF%FE=1`, {}],
      ['/%2e%2e/%2e%2e/etc/passwd', {}],
      ['/api/notes/%27%20OR%201%3D1--', {}],
      [paths.healthz, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: 'null' }],
    ];
    for (const [path, init] of attempts) {
      const res = await app.fetch(path, { ...init, sameOrigin: true });
      const text = await res.text();
      assert.ok(res.status < 500, `${init.method ?? 'GET'} ${path} answered ${res.status}: ${text.slice(0, 200)}`);
      assert.doesNotMatch(text, INTERNALS, `${init.method ?? 'GET'} ${path} leaked internals: ${text.slice(0, 300)}`);
    }
  });

  test('V16.5.1 an unexpected server error is answered generically and logged with the request id', async () => {
    // The test-mode bootstrap exposes no fault injection; a request that fails inside the stack is a JSON body
    // sent to a page route with an invalid charset and a hostile Accept header, which exercises the error handler.
    const res = await app.fetch(paths.login, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json; charset=unknown-x', Accept: 'application/x-unknown' },
      body: '\u0000{"x":1}',
    });
    const text = await res.text();
    assert.ok(res.status >= 400 && res.status < 600, `unexpected status ${res.status}`);
    assert.doesNotMatch(text, INTERNALS, `error response leaks internals: ${text.slice(0, 300)}`);
    if (res.status >= 500) {
      const events = await app.waitForEvent('error.unhandled');
      assert.ok(events.length >= 1, 'a 500 must produce an error.unhandled event carrying the request id');
      assert.ok(events.every((e) => typeof e.reqId === 'string' && e.reqId.length > 0));
    }
  });

  test('V16.5.3 error handling fails closed: an error on a protected route never renders protected content', async () => {
    const res = await app.fetch(`${paths.adminUsers}?page=%FF`, { headers: { Cookie: 'sid=' + 'A'.repeat(43) } });
    const text = await res.text();
    assert.ok([302, 303, 400, 401, 403, 404].includes(res.status), `protected route with a bogus session answered ${res.status}`);
    assert.doesNotMatch(text, new RegExp(users.member2.replace('.', '\\.')), 'no account data may appear on a denied response');
  });

  test('V13.4.3 the method is checked: unsupported methods on known paths are 404/405, never 500', async () => {
    for (const method of ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'PROPFIND']) {
      const res = await app.fetch(paths.login, { method, sameOrigin: false });
      const text = await res.text();
      assert.ok([403, 404, 405].includes(res.status) || (method === 'OPTIONS' && res.status === 204), `${method} /login answered ${res.status}`);
      assert.doesNotMatch(text, INTERNALS);
    }
  });

  test('RR-06 health and readiness endpoints answer quickly and are minimal', async () => {
    const started = Date.now();
    const health = await app.fetch(paths.healthz);
    assert.deepEqual(await health.json(), { status: 'ok' });
    assert.ok(Date.now() - started < 2_000, '/healthz must answer within 2 s');
    const ready = await app.fetch(paths.readyz);
    const readyBody = (await ready.json()) as { status: string };
    assert.equal(ready.status, 200, `/readyz must be ready once the app is listening (got ${ready.status})`);
    assert.equal(readyBody.status, 'ready');
    for (const path of [paths.healthz, paths.readyz]) {
      const res = await app.fetch(path);
      await res.text();
      assert.ok(!(res.headers.get('cache-control') ?? '').includes('max-age=3'), `${path} must not be cacheable for long`);
    }
  });

  test('RR-06 slow clients are cut off: a request that never completes its headers is closed by the headers timeout', async () => {
    const closedAfterMs = await new Promise<number>((resolve, reject) => {
      const started = Date.now();
      const socket = connect(app.port, '127.0.0.1', () => {
        socket.write('GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: ');
      });
      socket.setTimeout(40_000, () => {
        socket.destroy();
        reject(new Error('the server kept an incomplete request open for 40 s'));
      });
      socket.on('close', () => resolve(Date.now() - started));
      socket.on('error', () => resolve(Date.now() - started));
    });
    assert.ok(closedAfterMs <= 35_000, `incomplete request was closed after ${closedAfterMs} ms (headers timeout must be ~10 s)`);
    const health = await app.fetch(paths.healthz);
    assert.equal(health.status, 200, 'the server must still serve other clients');
    await health.text();
  });

  test('RR-06 the process shuts down gracefully on SIGTERM', async () => {
    const other = await startApp();
    const health = await other.fetch(paths.healthz);
    await health.text();
    assert.equal(health.status, 200);
    const exited = new Promise<{ code: number | null; signal: string | null }>((resolve) => other.child!.once('exit', (code, signal) => resolve({ code, signal })));
    other.child!.kill('SIGTERM');
    const result = await Promise.race([exited, new Promise<null>((r) => setTimeout(() => r(null), 15_000))]);
    await other.stop();
    assert.ok(result !== null, 'the app must exit within 15 s of SIGTERM');
    assert.ok(result.code === 0 || result.signal === 'SIGTERM', `unexpected exit: ${JSON.stringify(result)}`);
  });
});
