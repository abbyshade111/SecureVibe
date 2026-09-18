/** Data transfer objects (TPL-DTO-01): raw rows and secret columns never leave the server. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, fillPath, startApp, type RouteInfo, type RoutesExport, type RunningApp } from '../helpers/app.ts';
import { exampleNote, paths, users } from '../helpers/conventions.ts';

const FORBIDDEN_KEYS = /password|passwd|pwd|_hash$|^hash$|secret|totp|otp_|recovery|salt|hmac|token_hash|api_key_hash|must_change/i;
const FORBIDDEN_VALUES = [/^\$(argon2|scrypt|pbkdf2|bcrypt)\$?/, /^v\d+:[A-Za-z0-9+/=_-]{12,}:[A-Za-z0-9+/=_-]{12,}:/];

function scan(value: unknown, path: string, problems: string[]): void {
  if (Array.isArray(value)) {
    value.forEach((v, i) => scan(v, `${path}[${i}]`, problems));
    return;
  }
  if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (FORBIDDEN_KEYS.test(k)) problems.push(`${path}.${k}`);
      scan(v, `${path}.${k}`, problems);
    }
    return;
  }
  if (typeof value === 'string' && FORBIDDEN_VALUES.some((re) => re.test(value))) problems.push(`${path} = ${value.slice(0, 24)}...`);
}

describe('dto', () => {
  let app: RunningApp;
  let registry: RoutesExport;
  const jars: Record<string, CookieJar> = {};

  before(async () => {
    app = await startApp();
    registry = await app.routes();
    jars.member = await app.login(users.member);
    jars.admin = await app.login(users.admin);
  });
  after(async () => {
    await app?.stop();
  });

  function url(route: RouteInfo): string {
    const values: Record<string, string | number> = {};
    const entity = registry.entities.find((e) => e.name === route.owner?.entity || e.name === route.entity);
    if (entity) {
      values[route.owner?.param ?? 'id'] = entity.sample.id;
      values.id = entity.sample.id;
    }
    const admin = app.userByEmail(users.member);
    if (admin && /users?\//.test(route.path)) values.id = admin.id as string | number;
    return fillPath(route.path, values);
  }

  test('V15.3.1 JSON API responses contain only serializer fields: no hashes, secrets or encrypted blobs', async () => {
    const apiGets = registry.routes.filter((r) => r.method === 'GET' && (r.kind === 'api' || r.path.startsWith('/api')) && !r.path.startsWith('/__securevibe'));
    assert.ok(apiGets.length > 0, 'expected JSON API GET routes');
    const problems: string[] = [];
    let inspected = 0;
    for (const route of apiGets) {
      for (const who of ['member', 'admin'] as const) {
        const res = await app.fetch(url(route), { jar: jars[who], headers: { Accept: 'application/json' } });
        const text = await res.text();
        if (res.status !== 200 || !/application\/json/.test(res.headers.get('content-type') ?? '')) continue;
        inspected++;
        scan(JSON.parse(text), `${route.method} ${route.path} as ${who}`, problems);
      }
    }
    assert.ok(inspected > 0, 'at least one API response must have been inspected');
    assert.deepEqual(problems, [], `raw or secret fields leaked:\n${problems.join('\n')}`);
  });

  test('V15.3.1 pages never embed password hashes, encrypted seeds or session hashes', async () => {
    const pages = registry.routes.filter((r) => r.method === 'GET' && r.kind !== 'api' && !r.path.startsWith('/api') && !r.path.startsWith('/__securevibe'));
    const problems: string[] = [];
    for (const route of pages) {
      for (const who of ['member', 'admin'] as const) {
        const res = await app.fetch(url(route), { jar: jars[who] });
        const text = await res.text();
        if (res.status !== 200) continue;
        if (/\$argon2id\$|\$scrypt\$/.test(text)) problems.push(`${route.path} as ${who}: password hash`);
        if (/v\d+:[A-Za-z0-9+/=_-]{12,}:[A-Za-z0-9+/=_-]{20,}:[A-Za-z0-9+/=_-]{8,}/.test(text)) problems.push(`${route.path} as ${who}: encrypted blob`);
        const sessions = app.dbAll<{ id_hash: string }>('SELECT id_hash FROM sessions');
        if (sessions.some((s) => text.includes(s.id_hash))) problems.push(`${route.path} as ${who}: full session hash`);
      }
    }
    assert.deepEqual(problems, [], `sensitive values rendered:\n${problems.join('\n')}`);
  });

  test('V8.2.3 the owner and admin serializers expose only the fields each audience may see', async (t) => {
    if (!(await app.featureEnabled('example'))) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const create = await app.json('POST', paths.notesApi, exampleNote, jars.member!);
    const created = (await create.json()) as Record<string, unknown>;
    const note = (created.data ?? created.note ?? created) as Record<string, unknown>;
    assert.ok(typeof note.id === 'string' || typeof note.id === 'number', 'the DTO must expose the id');
    assert.equal(note.title, exampleNote.title);
    const internal = Object.keys(note).filter((k) => /^_|rowid|internal|deleted_at|owner_hash/i.test(k));
    assert.deepEqual(internal, [], `internal columns leaked from the DTO: ${internal.join(', ')}`);
  });

  test('V15.3.1 the account and admin user views never expose another user\'s private fields to a member', async () => {
    const res = await app.fetch(paths.account, { jar: jars.member, headers: { Accept: 'application/json' } });
    const text = await res.text();
    assert.equal(res.status, 200);
    assert.equal(text.includes(users.member2), false, "the member's account view must not list other users");
    assert.equal(text.includes(app.env.SECUREVIBE_TEST_TOTP_SEED!), false);
  });
});
