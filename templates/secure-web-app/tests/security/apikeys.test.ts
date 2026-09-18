/** API keys for the public JSON API (contract §1.12, TPL-APIKEY-01). Skips when the public-api feature is off. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, fillPath, startApp, type RouteInfo, type RunningApp } from '../helpers/app.ts';
import { exampleNote, fields, paths, users } from '../helpers/conventions.ts';
import { skipReason } from '../helpers/features.ts';

const KEY_FORMAT = /\bsk_[A-Za-z0-9]{8}_[A-Za-z0-9_-]{43}\b/;

describe('apikeys', () => {
  let app: RunningApp;
  let enabled = false;
  let member: CookieJar;
  let key: string | undefined;
  let apiRoute: RouteInfo | undefined;

  before(async () => {
    app = await startApp();
    enabled = await app.featureEnabled('public-api');
    if (!enabled) return;
    member = await app.login(users.member);
    const { routes } = await app.routes();
    apiRoute =
      routes.find((r) => r.method === 'GET' && r.auth === 'user' && r.path.startsWith(paths.apiV1) && !r.path.includes(':')) ??
      routes.find((r) => r.method === 'GET' && r.auth === 'user' && (r.kind === 'api' || r.path.startsWith('/api')) && !r.path.includes(':'));
  });
  after(async () => {
    await app?.stop();
  });

  async function createKey(jar: CookieJar): Promise<string> {
    const res = await app.submitForm(paths.apiKeys, { [fields.label]: 'security test' }, jar, { headers: { Accept: 'application/json, text/html' } });
    let text = await res.text();
    if (res.status >= 300 && res.status < 400) text = (await app.page(res.headers.get('location') ?? paths.apiKeys, jar)).html;
    const m = text.match(KEY_FORMAT);
    assert.ok(m, `creating a key must show it once in the sk_<prefix>_<secret> format: ${res.status} ${text.slice(0, 300)}`);
    return m[0];
  }

  test('V14.2.1 API keys are accepted only as a Bearer header; keys in the query string are rejected with 400', async (t) => {
    if (!enabled) return t.skip(skipReason('public-api'));
    assert.ok(apiRoute, 'expected a user-level JSON API GET route to call with an API key');
    key = await createKey(member);
    const url = fillPath(apiRoute.path, {});
    const bearer = await app.fetch(url, { headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' } });
    const bearerBody = await bearer.text();
    assert.equal(bearer.status, 200, `Bearer key must be accepted: ${bearer.status} ${bearerBody.slice(0, 200)}`);
    for (const param of ['api_key', 'apiKey', 'key', 'token', 'access_token']) {
      const q = await app.fetch(`${url}?${param}=${encodeURIComponent(key)}`, { headers: { Accept: 'application/json' } });
      const qBody = await q.text();
      assert.equal(q.status, 400, `a key in ?${param}= must be rejected with 400 (got ${q.status}): ${qBody.slice(0, 200)}`);
    }
    const anon = await app.fetch(url, { headers: { Accept: 'application/json' } });
    await anon.text();
    assert.ok([401, 403].includes(anon.status) || (anon.status >= 300 && anon.status < 400), `without a key the route must be denied (got ${anon.status})`);
    assert.equal(app.logText().includes(key), false, 'the full key must never be logged');
  });

  test('V11.5.1 API keys are CSPRNG secrets (256 bits) stored only as HMAC hashes with a lookup prefix', async (t) => {
    if (!enabled) return t.skip(skipReason('public-api'));
    assert.ok(key);
    const secret = key.split('_').slice(2).join('_');
    assert.equal(Buffer.from(secret, 'base64url').length, 32, 'the secret part must encode 32 random bytes');
    assert.equal(app.dbContains(secret), false, 'the key secret must not be stored in clear');
    assert.equal(app.dbContains(key), false, 'the full key must not be stored in clear');
    const table = app.dbTables().find((n) => /api_?keys?/i.test(n));
    assert.ok(table, 'an api_keys table must exist');
    const rows = app.dbAll<Record<string, unknown>>(`SELECT * FROM ${table}`);
    assert.ok(rows.length >= 1);
    const row = rows[rows.length - 1]!;
    assert.equal(String(row.prefix), key.split('_')[1]);
    assert.match(String(row.hash), /^[0-9a-f]{64}$/i, 'the hash must be an HMAC-SHA256 digest');
    for (const col of ['user_id', 'scopes', 'created_at', 'last_used_at', 'revoked_at']) assert.ok(col in row, `${table} lacks column ${col}`);
    const second = await createKey(member);
    assert.notEqual(second, key);
  });

  test('V8.2.1 API-key requests act as the key owner, skip CSRF, and a revoked key stops working', async (t) => {
    if (!enabled) return t.skip(skipReason('public-api'));
    assert.ok(key && apiRoute);
    const url = fillPath(apiRoute.path, {});
    const adminRoute = (await app.routes()).routes.find((r) => r.method === 'GET' && r.auth === 'role:admin' && !r.path.includes(':'));
    if (adminRoute) {
      const res = await app.fetch(fillPath(adminRoute.path, {}), { headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' } });
      await res.text();
      const deniedByRedirect = res.status >= 300 && res.status < 400 && /login|sign-?in/i.test(res.headers.get('location') ?? '');
      assert.ok([401, 403, 404].includes(res.status) || deniedByRedirect, `a member's key must not open admin routes (got ${res.status})`);
    }
    if (await app.featureEnabled('example')) {
      const create = await app.fetch(paths.notesApi, {
        method: 'POST',
        headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(exampleNote),
        sameOrigin: false,
      });
      const body = await create.text();
      assert.ok([200, 201].includes(create.status), `API-key callers do not use sessions and need no CSRF token: ${create.status} ${body.slice(0, 200)}`);
    }
    const table = app.dbTables().find((n) => /api_?keys?/i.test(n))!;
    const row = app.dbAll<{ id: string | number; prefix: string }>(`SELECT id, prefix FROM ${table} WHERE prefix = ?`, key.split('_')[1]!)[0];
    assert.ok(row, 'the key row must be found by prefix');
    const revoke = await app.submitForm(paths.apiKeyRevoke(String(row.id)), {}, member, { csrfFrom: paths.apiKeys });
    await revoke.text();
    assert.ok(revoke.status < 400, `revoke failed: ${revoke.status}`);
    const after = await app.fetch(url, { headers: { Authorization: `Bearer ${key}`, Accept: 'application/json' } });
    await after.text();
    assert.ok([401, 403].includes(after.status), `a revoked key must be rejected (got ${after.status})`);
    const wrong = await app.fetch(url, { headers: { Authorization: `Bearer sk_${key.split('_')[1]}_${'A'.repeat(43)}`, Accept: 'application/json' } });
    await wrong.text();
    assert.ok([401, 403].includes(wrong.status), 'a key with a valid prefix but wrong secret must be rejected');
  });
});
