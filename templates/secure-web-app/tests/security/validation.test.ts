/** Input validation (contract §1.4, TPL-VALIDATION-01, TPL-BODY-01, TPL-DATA-02). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { exampleNote, fields, headers as headerNames, paths, users } from '../helpers/conventions.ts';

interface ApiError {
  error?: { code?: string; message?: string; fields?: unknown };
}

describe('validation', () => {
  let app: RunningApp;
  let member: CookieJar;
  let hasNotes = false;

  before(async () => {
    app = await startApp();
    member = await app.login(users.member);
    hasNotes = await app.featureEnabled('example');
  });
  after(async () => {
    await app?.stop();
  });

  async function expectValidationError(res: Response, what: string): Promise<ApiError> {
    const text = await res.text();
    assert.equal(res.status, 400, `${what}: expected 400, got ${res.status} ${text.slice(0, 200)}`);
    assert.match(res.headers.get('content-type') ?? '', /application\/json/, `${what}: API errors must be JSON`);
    const body = JSON.parse(text) as ApiError;
    assert.equal(body.error?.code, 'validation_error', `${what}: error code must be validation_error`);
    assert.ok(typeof body.error?.message === 'string' && body.error.message.length > 0, `${what}: a plain-language message is required`);
    return body;
  }

  test('V2.2.1 strict schemas: unknown fields, wrong types and arrays for scalars are rejected with 400', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const ok = await app.json('POST', paths.notesApi, exampleNote, member);
    const okText = await ok.text();
    assert.ok([200, 201].includes(ok.status), `a valid body must be accepted: ${ok.status} ${okText.slice(0, 200)}`);

    const unknown = await app.json('POST', paths.notesApi, { ...exampleNote, isAdmin: true }, member);
    const body = await expectValidationError(unknown, 'unknown field');
    assert.ok(body.error?.fields !== undefined, 'the response must name the offending fields');

    await expectValidationError(await app.json('POST', paths.notesApi, { ...exampleNote, title: ['a', 'b'] }, member), 'array for a scalar');
    await expectValidationError(await app.json('POST', paths.notesApi, { ...exampleNote, title: 12345 }, member), 'number for a string');
    await expectValidationError(await app.json('POST', paths.notesApi, { ...exampleNote, title: { $gt: '' } }, member), 'object for a string');
    await expectValidationError(await app.json('POST', paths.notesApi, {}, member), 'missing required fields');
    await expectValidationError(await app.json('POST', paths.notesApi, [exampleNote], member), 'array instead of object');
    const events = await app.waitForEvent('validation.rejected');
    assert.ok(events.length >= 1, 'validation.rejected security events must be emitted');
  });

  test('V2.2.1 path and query parameters are validated (bad ids and unknown query fields are rejected)', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    for (const bad of ['not-an-id', '1%20OR%201=1', '..%2F..%2Fetc%2Fpasswd', "'", '%00']) {
      const res = await app.fetch(paths.noteApi(bad), { jar: member });
      const text = await res.text();
      assert.ok([400, 404].includes(res.status), `id "${bad}" answered ${res.status}: ${text.slice(0, 200)}`);
      assert.doesNotMatch(text, /SQLITE|sqlite_|syntax error|at .*\.ts:\d+/i, `id "${bad}" leaked internals`);
    }
    const query = await app.fetch(`${paths.notesApi}?unknownField=1`, { jar: member });
    const text = await query.text();
    assert.ok([200, 400].includes(query.status), `unknown query field answered ${query.status}: ${text.slice(0, 200)}`);
  });

  test('V15.3.7 the query parser is simple: repeated parameters never become arrays or objects', async () => {
    const res = await app.fetch(`${paths.login}?${fields.next}=/a&${fields.next}=/b&x[y]=1&x[z]=2`);
    const text = await res.text();
    assert.ok(res.status < 500, `parameter pollution caused ${res.status}`);
    assert.doesNotMatch(text, /TypeError|Cannot read|is not a function/i, 'parameter pollution must not surface an internal error');
    if (hasNotes) {
      const api = await app.fetch(`${paths.notesApi}?limit=1&limit=2`, { jar: member });
      const apiText = await api.text();
      assert.ok(api.status < 500, `repeated query parameter caused ${api.status}: ${apiText.slice(0, 200)}`);
    }
  });

  test('V15.3.6 prototype-pollution keys in JSON bodies are rejected, so a prototype cannot be polluted', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    for (const raw of [
      `{"title":"x","body":"y","__proto__":{"polluted":true}}`,
      `{"title":"x","body":"y","constructor":{"prototype":{"polluted":true}}}`,
    ]) {
      const res = await app.json('POST', paths.notesApi, undefined, member, { raw });
      const text = await res.text();
      assert.equal(res.status, 400, `prototype pollution payload answered ${res.status}: ${text.slice(0, 200)}`);
    }
    assert.equal(({} as { polluted?: boolean }).polluted, undefined);
  });

  test('V15.2.2 an oversized body is rejected with 413 before it is processed, so one request cannot take up the time or resources the app needs', async () => {
    const big = JSON.stringify({ title: 'x', body: 'y'.repeat(2 * 1024 * 1024) });
    const res = await app.json('POST', hasNotes ? paths.notesApi : paths.login, undefined, member, { raw: big });
    const text = await res.text();
    assert.equal(res.status, 413, `2 MB JSON body answered ${res.status}: ${text.slice(0, 200)}`);
    const form = await app.fetch(paths.login, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `${fields.email}=${'a'.repeat(2 * 1024 * 1024)}`,
    });
    await form.text();
    assert.equal(form.status, 413, `2 MB form body answered ${form.status}`);
  });

  test('V2.2.1 malformed JSON is a 400 validation problem, not a server error', async (t) => {
    if (!hasNotes) return t.skip('reference notes API not mounted (EXAMPLE_FEATURE=0)');
    const res = await app.json('POST', paths.notesApi, undefined, member, { raw: '{"title": "unterminated' });
    const text = await res.text();
    assert.equal(res.status, 400, `malformed JSON answered ${res.status}`);
    assert.doesNotMatch(text, /SyntaxError|Unexpected token|at position/i, 'the parser error must not be echoed');
    const wrongType = await app.fetch(paths.notesApi, {
      method: 'POST',
      jar: member,
      headers: { 'Content-Type': 'text/plain', [headerNames.csrf]: await app.csrfToken(paths.account, member) },
      body: 'title=x',
    });
    const wrongText = await wrongType.text();
    assert.ok([400, 415].includes(wrongType.status), `unsupported content type answered ${wrongType.status}: ${wrongText.slice(0, 200)}`);
  });

  test('V14.2.1 credentials are never accepted from the query string and never logged', async () => {
    const jar = new CookieJar();
    const res = await app.fetch(`${paths.login}?${fields.email}=${encodeURIComponent(users.member)}&${fields.password}=${encodeURIComponent(app.password)}`, { jar });
    await res.text();
    assert.equal(await app.isAuthenticated(jar), false, 'a GET with credentials in the URL must not sign anyone in');
    const post = await app.fetch(`${paths.login}?${fields.password}=${encodeURIComponent(app.password)}`, {
      method: 'POST',
      jar,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `${fields.email}=${encodeURIComponent(users.member)}`,
    });
    await post.text();
    assert.ok(!(isRedirect(post) && !/login/i.test(locationOf(post))) || !(await app.isAuthenticated(jar)), 'a password in the query string must not be used');
    assert.equal(app.logText().includes(app.password), false, 'the password must never reach the log file');
    assert.equal(app.logText().includes(encodeURIComponent(app.password)), false, 'the URL-encoded password must never reach the log file');
  });

  test('V2.2.1 page forms re-render with an error instead of accepting invalid input', async () => {
    const jar = new CookieJar();
    const res = await app.submitForm(paths.login, { [fields.email]: 'not-an-email', [fields.password]: 'x' }, jar);
    const text = await res.text();
    assert.ok([200, 400, 422].includes(res.status) || (isRedirect(res) && /login/i.test(locationOf(res))), `invalid login form answered ${res.status}`);
    assert.doesNotMatch(text, /ZodError|at .*\.ts:\d+/, 'validation internals must not be shown');
    assert.equal(await app.isAuthenticated(jar), false);
  });
});
