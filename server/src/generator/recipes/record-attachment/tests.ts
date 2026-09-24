/**
 * Test emitter for the record-attachment recipe.
 *
 * These tests are about what this recipe decides: which record a file belongs to, who may attach one, and that the
 * column cannot be set any other way. What the uploads module decides — the size cap, the storage location, the
 * download headers — is tested by the template's own `tests/security/uploads.test.ts`, and is not claimed again
 * here. The one exception is the file-type check: it runs on this recipe's own route, and a route that forgot to go
 * through the module would pass every test in the template while accepting anything at all, so it is worth proving
 * at the route this recipe adds.
 *
 * The names carry their requirement id at the front (that is how `compliance/evidence.ts` credits a test) and then
 * restate the requirement in the same plain words the reports use.
 */
import type { RecipeRequirement } from '../types.js';
import { commentText } from '../js-literal.js';
import { payloadLiteral } from '../record-type/tests.js';
import type { AttachmentPlan } from './emit.js';

export interface EmittedTest {
  name: string;
  code: string;
  requirement?: Omit<RecipeRequirement, 'test'>;
}

export function attachmentTests(plan: AttachmentPlan): EmittedTest[] {
  const entity = plan.entity;
  const name = entity.entity.name;
  const lower = entity.entity.label.toLowerCase();
  const first = plan.fields[0]!;
  const signIn = entity.adminOnly ? 'users.admin' : 'users.member';
  const tests: EmittedTest[] = [];

  tests.push({
    name: `${name}: a file can be attached to a record, seen on its files page and removed again`,
    code: `  test('${name}: a file can be attached to a record, seen on its files page and removed again', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(${signIn});
    const id = await createRecord(jar);

    const attached = await attach(jar, id, { name: 'picture.png', type: 'image/png', bytes: png() });
    await attached.text();
    assert.ok(attached.status < 400, \`attaching a file must be accepted (got \${attached.status})\`);

    const { html } = await app.page(filesPath(id), jar);
    assert.match(html, /picture\\.png/, 'the files page must show the attached file');
    const uploadId = html.match(/\\/uploads\\/([0-9a-f-]{36})/)?.[1];
    assert.ok(uploadId, 'the files page must link to the stored file');

    const removed = await app.submitForm(\`\${filesPath(id)}/${first.column}/remove\`, {}, jar, { csrfFrom: filesPath(id) });
    await removed.text();
    assert.ok(removed.status < 400, \`removing the file must be accepted (got \${removed.status})\`);
    const after = await app.page(filesPath(id), jar);
    assert.doesNotMatch(after.html, /picture\\.png/, 'the files page must no longer show the removed file');
    const gone = await app.fetch(\`/uploads/\${uploadId}\`, { jar });
    await gone.text();
    assert.ok(gone.status === 404 || gone.status === 403, \`the removed file must no longer be downloadable (got \${gone.status})\`);
  });`,
  });

  tests.push({
    name: `V5.2.2 ${name}: the app looks inside an attached file and refuses one that is not really the type its name claims`,
    requirement: {
      standard: 'asvs',
      id: 'V5.2.2',
      proves: `A file named as a picture but holding something else is refused when it is attached to ${/^[aeiou]/.test(lower) ? 'an' : 'a'} ${lower}, and nothing is attached.`,
    },
    code: `  test('V5.2.2 ${name}: the app looks inside an attached file and refuses one that is not really the type its name claims', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(${signIn});
    const id = await createRecord(jar);

    // The name and the declared type both say PNG; the bytes say otherwise.
    const res = await attach(jar, id, { name: 'picture.png', type: 'image/png', bytes: Buffer.from('<?php echo "not a picture"; ?>') });
    await res.text();
    assert.equal(res.status, 415, \`a file that is not the type it claims must be refused (got \${res.status})\`);
    const { html } = await app.page(filesPath(id), jar);
    assert.doesNotMatch(html, /picture\\.png/, 'nothing may be attached when the file was refused');
  });`,
  });

  tests.push({
    name: `V3.5.1 ${name}: attaching a file needs the secret token, so another site cannot attach one for a signed-in person`,
    requirement: {
      standard: 'asvs',
      id: 'V3.5.1',
      proves: 'The attach route reads a multipart body, so the usual token check cannot run before it; this shows the uploads module still refuses a request with no token and one from another site.',
    },
    code: `  test('V3.5.1 ${name}: attaching a file needs the secret token, so another site cannot attach one for a signed-in person', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(${signIn});
    const id = await createRecord(jar);

    const noToken = await attach(jar, id, { name: 'picture.png', type: 'image/png', bytes: png() }, { token: null });
    await noToken.text();
    assert.equal(noToken.status, 403, \`an attach with no token must be refused (got \${noToken.status})\`);

    const foreign = await attach(jar, id, { name: 'picture.png', type: 'image/png', bytes: png() }, { origin: 'https://evil.example' });
    await foreign.text();
    assert.equal(foreign.status, 403, \`an attach from another site must be refused (got \${foreign.status})\`);

    const { html } = await app.page(filesPath(id), jar);
    assert.doesNotMatch(html, /picture\\.png/, 'nothing may be attached by a refused request');
  });`,
  });

  tests.push({
    name: `V8.2.1 ${name}: attaching a file is not an action available without signing in`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.1',
      proves: 'Someone who has not signed in cannot attach a file or read the page that lists them.',
    },
    code: `  test('V8.2.1 ${name}: attaching a file is not an action available without signing in', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const owner = await app.login(${signIn});
    const id = await createRecord(owner);

    const page = await app.fetch(filesPath(id), { jar: new CookieJar() });
    const body = await page.text();
    assert.ok(refusedAnonymously(page), \`the files page must not be readable without signing in (got \${page.status} \${locationOf(page)})\`);
    assert.doesNotMatch(body, /Attach/, 'the attach form must not be served to a visitor who has not signed in');

    const res = await attach(new CookieJar(), id, { name: 'picture.png', type: 'image/png', bytes: png() }, { token: null });
    await res.text();
    assert.ok(refusedAnonymously(res), \`attaching without signing in must be refused (got \${res.status})\`);
  });`,
  });

  tests.push({
    name: `V8.2.3 ${name}: the file is not a field the record\u2019s own interface can set, only attaching one sets it`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.3',
      proves: `The ${first.label.toLowerCase()} column is writable only by attaching a file, so a caller cannot point ${/^[aeiou]/.test(lower) ? 'an' : 'a'} ${lower} at a stored file of their choosing — including one belonging to somebody else.`,
    },
    code: `  test('V8.2.3 ${name}: the file is not a field the record\u2019s own interface can set, only attaching one sets it', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(${signIn});
    const id = await createRecord(jar);
    const read = await app.fetch(\`\${API}/\${id}\`, { jar, headers: { Accept: 'application/json' } });
    const record = (await read.json()) as Record<string, unknown> & { updatedAt: string };

    const res = await app.json('PATCH', \`\${API}/\${id}\`, { ${first.prop}: '00000000-0000-4000-8000-000000000000', updatedAt: record.updatedAt }, jar);
    await res.text();
    assert.equal(res.status, 400, \`the record's interface must not accept a ${first.label.toLowerCase()} value (got \${res.status})\`);
  });`,
  });

  if (entity.ownerScoped) {
    tests.push({
      name: `V8.2.2 ${name}: changing the id in the address to a record owned by someone else attaches nothing to it`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.2',
        proves: `Attaching a file to somebody else’s ${lower} is refused, and that record keeps whatever it had.`,
      },
      code: `  test('V8.2.2 ${name}: changing the id in the address to a record owned by someone else attaches nothing to it', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const owner = await app.login(users.member);
    const id = await createRecord(owner);

    const other = await app.login(users.member2);
    const page = await app.fetch(filesPath(id), { jar: other });
    await page.text();
    assert.ok(page.status === 403 || page.status === 404, \`another person must not read the files page (got \${page.status})\`);

    const res = await attach(other, id, { name: 'intruder.png', type: 'image/png', bytes: png() });
    await res.text();
    assert.ok(res.status === 403 || res.status === 404, \`another person must not attach a file (got \${res.status})\`);

    const { html } = await app.page(filesPath(id), owner);
    assert.doesNotMatch(html, /intruder\\.png/, "another person's file must not be attached to this record");
  });`,
    });
  }

  return tests;
}

export function attachmentRequirements(plan: AttachmentPlan): RecipeRequirement[] {
  return attachmentTests(plan)
    .filter((t): t is EmittedTest & { requirement: NonNullable<EmittedTest['requirement']> } => t.requirement !== undefined)
    .map((t) => ({ ...t.requirement, test: t.name }));
}

export function emitTest(plan: AttachmentPlan, runId: string): string {
  const entity = plan.entity;
  return `// Generated by SecureVibe (recipe record-attachment) — run ${runId}
/** Files attached to ${commentText(entity.entity.label)} records: who may attach one, and what is refused. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { fields, users } from '../helpers/conventions.ts';

const BASE = '${plan.base}';
const API = '/api${plan.base}';
const SKIP = 'the uploads feature is switched off for this app';

/** A body for creating one record, the same shape the record's own tests use. */
const PAYLOAD = ${payloadLiteral(entity, 'a')};

/** The first eight bytes of a real PNG, so the type check sees what the name claims. */
const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
function png(size = 512): Buffer {
  return Buffer.concat([PNG_MAGIC, Buffer.alloc(Math.max(0, size - PNG_MAGIC.length), 7)]);
}

describe('${entity.entity.name} files', () => {
  let app: RunningApp;
  let enabled = false;

  before(async () => {
    app = await startApp();
    enabled = await app.featureEnabled('uploads');
  });
  after(async () => {
    await app?.stop();
  });

  function filesPath(id: string): string {
    return \`\${BASE}/\${id}/files\`;
  }

  /** A page refuses an anonymous visitor either outright or by sending them to the sign-in page. */
  function refusedAnonymously(res: Response): boolean {
    return res.status === 401 || res.status === 403 || (isRedirect(res) && /login|sign-?in/i.test(locationOf(res)));
  }

  /** Creates one record through the record's own interface and returns its id. */
  async function createRecord(jar: CookieJar): Promise<string> {
    const res = await app.json('POST', API, PAYLOAD, jar);
    const body = (await res.json()) as { id: string };
    assert.equal(res.status, 201, 'the record must be created for the test to attach to');
    return body.id;
  }

  /**
   * Sends one multipart attach request. \`token: null\` leaves the form token out, and \`origin\` pretends the form
   * was submitted by another site.
   */
  async function attach(
    jar: CookieJar,
    id: string,
    file: { name: string; type: string; bytes: Buffer },
    opts: { token?: string | null; origin?: string } = {},
  ): Promise<Response> {
    const token = opts.token === undefined ? await app.csrfToken(filesPath(id), jar) : opts.token;
    const form = new FormData();
    // The token is written before the file, because the uploads module checks it as the stream arrives.
    if (token) form.append(fields.csrf, token);
    form.append('file', new Blob([new Uint8Array(file.bytes)], { type: file.type }), file.name);
    return app.fetch(\`\${filesPath(id)}/${plan.fields[0]!.column}\`, {
      method: 'POST',
      jar,
      body: form,
      headers: { Accept: 'text/html', ...(opts.origin ? { Origin: opts.origin } : {}) },
    });
  }

${attachmentTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
