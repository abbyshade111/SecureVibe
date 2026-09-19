/**
 * Test emitter for the record-type recipe. Every generated feature ships the checks the Security Contract
 * requires (SC-17) — anonymous denied, wrong role denied, validation rejects bad input, ownership enforced —
 * plus a create/read/update/delete round trip, a page-size cap and a check that each audience only sees the
 * fields meant for it.
 *
 * `recordTypeTests()` is the single source of both the emitted file and the recipe's requirement mapping: a
 * test's `requirement` is what makes it count as evidence, and the name it is emitted under is the same string
 * the mapping reports. The compliance engine credits a test to a requirement when the test's own name *starts*
 * with the requirement id (`compliance/evidence.ts`), so these names are load-bearing — do not reword the id
 * out of the front of one.
 */
import type { RecipeRequirement } from '../types.js';
import type { EntityPlan, FieldPlan } from './fields.js';

/** One test the recipe emits: its name, the code of the `test(...)` call, and what (if anything) it evidences. */
export interface EmittedTest {
  name: string;
  code: string;
  requirement?: Omit<RecipeRequirement, 'test'>;
}

/** A valid value for a field, used to build a create/update payload in the generated tests. */
function sampleValue(f: FieldPlan, variant: 'a' | 'b'): string {
  const suffix = variant === 'a' ? 'one' : 'two';
  switch (f.control) {
    case 'number':
      return variant === 'a' ? '1' : '2';
    case 'money':
      return variant === 'a' ? '9.99' : '19.99';
    case 'checkbox':
      return variant === 'a' ? "'on'" : "'on'";
    case 'date':
      return variant === 'a' ? "'2026-01-01'" : "'2026-02-02'";
    case 'datetime-local':
      return variant === 'a' ? "'2026-01-01T09:00'" : "'2026-02-02T10:30'";
    case 'email':
      return variant === 'a' ? "'sample.one@example.com'" : "'sample.two@example.com'";
    case 'url':
      return "'https://example.com'";
    case 'tel':
      return "'+1 555 0100'";
    case 'select': {
      const choices = f.field.choices ?? [];
      const pick = variant === 'a' ? choices[0] : (choices[1] ?? choices[0]);
      return JSON.stringify(pick ?? '');
    }
    case 'textarea':
      return `'Sample text ${suffix}'`;
    default:
      return `'Sample ${suffix}'`;
  }
}

/** A value of the wrong shape for the field, so the validation test has something the schema must refuse. */
function invalidValue(f: FieldPlan): string {
  switch (f.control) {
    case 'number':
    case 'money':
      return "'not-a-number'";
    case 'select':
      return "'not-a-choice'";
    case 'email':
      return "'not-an-email'";
    case 'url':
      return "'not-a-web-address'";
    case 'date':
    case 'datetime-local':
      return "'yesterday'";
    default:
      return "''";
  }
}

/**
 * The tests the recipe emits for one record type, in the order they appear in the file. The mapping each one
 * carries is a statement about what that test checks — the evidence is the test result itself.
 */
export function recordTypeTests(plan: EntityPlan): EmittedTest[] {
  const name = plan.entity.name;
  const signIn = plan.adminOnly ? 'users.admin' : 'users.member';
  const requiredField = plan.fields.find((f) => f.field.required);
  const invalidPayload = requiredField
    ? `{ ...PAYLOAD_A, ${requiredField.prop}: ${invalidValue(requiredField)} }`
    : `{ ...PAYLOAD_A, somethingUnknown: 'x' }`;
  const sensitive = plan.fields.filter((f) => f.field.sensitive);
  const tests: EmittedTest[] = [];

  tests.push({
    name: `V8.2.1 ${name}: no page or action is available without signing in, and anything not explicitly allowed is refused`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.1',
      proves: `Calling the ${plan.entity.label.toLowerCase()} interface without signing in is refused${plan.publicRead ? ' for anything that changes data' : ''}.`,
    },
    code: `  test('V8.2.1 ${name}: no page or action is available without signing in, and anything not explicitly allowed is refused', async () => {
    const res = await app.fetch(API, { jar: new CookieJar() });
    await res.text();
    ${plan.publicRead ? `assert.ok(res.status === 200 || res.status === 401, 'a public list either answers or asks for a sign-in');` : `assert.ok(res.status === 401 || res.status === 403, \`expected a denial, got \${res.status}\`);`}
    const write = await app.json('POST', API, PAYLOAD_A, new CookieJar());
    await write.text();
    assert.ok(write.status === 401 || write.status === 403, \`creating without signing in must be refused, got \${write.status}\`);
  });`,
  });

  tests.push({
    name: `V2.2.1 ${name}: input is checked against what is expected before the app uses it`,
    requirement: {
      standard: 'asvs',
      id: 'V2.2.1',
      proves: `A value of the wrong kind in a ${plan.entity.label.toLowerCase()} is refused rather than stored.`,
    },
    code: `  test('V2.2.1 ${name}: input is checked against what is expected before the app uses it', async () => {
    const jar = await app.login(${signIn});
    const res = await app.json('POST', API, ${invalidPayload}, jar);
    await res.text();
    assert.equal(res.status, 400, 'invalid input must be refused with 400');
  });`,
  });

  tests.push({
    name: `V2.2.2 ${name}: input checks happen on the server, not only in the browser`,
    requirement: {
      standard: 'asvs',
      id: 'V2.2.2',
      proves: 'The rules are enforced by the server itself: a call made straight to the interface, with no browser involved, cannot set a field that was not meant to be writable.',
    },
    code: `  test('V2.2.2 ${name}: input checks happen on the server, not only in the browser', async () => {
    const jar = await app.login(${signIn});
    // Sent straight to the interface, with no page and no browser checks in the way.
    const unknown = await app.json('POST', API, { ...PAYLOAD_A, notAField: 'x' }, jar);
    await unknown.text();
    assert.equal(unknown.status, 400, 'unknown fields must be refused (mass assignment)');
    const ownerOverride = await app.json('POST', API, { ...PAYLOAD_A, ownerId: 'someone-else' }, jar);
    await ownerOverride.text();
    assert.equal(ownerOverride.status, 400, 'the owner of a record cannot be set by the caller');
  });`,
  });

  tests.push({
    name: `${name}: create, read, update and delete work for the owner`,
    code: `  test('${name}: create, read, update and delete work for the owner', async () => {
    const jar = await app.login(${signIn});
    const created = await app.json('POST', API, PAYLOAD_A, jar);
    const record = (await created.json()) as { id: string; updatedAt: string };
    assert.equal(created.status, 201, 'the record must be created');
    assert.ok(record.id, 'the created record must have an id');

    const read = await app.fetch(\`\${API}/\${record.id}\`, { jar });
    assert.equal(read.status, 200, 'the owner must be able to read it back');
    await read.text();

    const updated = await app.json('PATCH', \`\${API}/\${record.id}\`, { ...PAYLOAD_B, updatedAt: record.updatedAt }, jar);
    assert.equal(updated.status, 200, \`the owner must be able to update it (got \${updated.status})\`);
    await updated.text();

    const removed = await app.json('DELETE', \`\${API}/\${record.id}\`, undefined, jar);
    assert.equal(removed.status, 204, 'the owner must be able to delete it');
    await removed.text();
  });`,
  });

  tests.push({
    name: `V2.3.3 ${name}: either all of a change happens or none of it does, leaving no half-finished change behind`,
    requirement: {
      standard: 'asvs',
      id: 'V2.3.3',
      proves:
        'A change based on an out-of-date version of the record is refused whole: nothing is half-applied, and reading the record back afterwards gives exactly what was there before the attempt.',
    },
    code: `  test('V2.3.3 ${name}: either all of a change happens or none of it does, leaving no half-finished change behind', async () => {
    const jar = await app.login(${signIn});
    const created = await app.json('POST', API, PAYLOAD_A, jar);
    const first = (await created.json()) as Record<string, unknown> & { id: string; updatedAt: string };
    assert.equal(created.status, 201);

    // One change goes through, which makes the version the browser first saw out of date.
    const updated = await app.json('PATCH', \`\${API}/\${first.id}\`, { ...PAYLOAD_B, updatedAt: first.updatedAt }, jar);
    await updated.text();
    assert.equal(updated.status, 200, 'the first change must be saved');
    // Read through the same route the check below uses, so the two are compared like with like.
    const before = await app.fetch(\`\${API}/\${first.id}\`, { jar, headers: { Accept: 'application/json' } });
    const settled = (await before.json()) as Record<string, unknown>;

    // A second change built on the stale version must be refused, not merged.
    const stale = await app.json('PATCH', \`\${API}/\${first.id}\`, { ...PAYLOAD_A, updatedAt: first.updatedAt }, jar);
    await stale.text();
    assert.ok([400, 409, 412, 422].includes(stale.status), \`a change based on an out-of-date version must be refused, got \${stale.status}\`);

    // And nothing of it may have landed: the record is what the successful change left behind.
    const after = await app.fetch(\`\${API}/\${first.id}\`, { jar, headers: { Accept: 'application/json' } });
    assert.equal(after.status, 200, 'the record must still be readable');
    assert.deepEqual(await after.json(), settled, 'the refused change must have left the record untouched');
  });`,
  });

  tests.push({
    name: `V2.4.1 ${name}: asking for an unreasonable number of records at once cannot copy all the data`,
    requirement: {
      standard: 'asvs',
      id: 'V2.4.1',
      proves: 'Asking for a huge page of records is either refused or capped, so the list cannot be used to pull everything out in one call.',
    },
    code: `  test('V2.4.1 ${name}: asking for an unreasonable number of records at once cannot copy all the data', async () => {
    const jar = await app.login(${signIn});
    const res = await app.fetch(\`\${API}?limit=100000\`, { jar, headers: { Accept: 'application/json' } });
    const text = await res.text();
    if (res.status === 400) return; // an oversized page size is refused outright
    assert.equal(res.status, 200, \`the list must answer (got \${res.status})\`);
    const body = JSON.parse(text) as { records: unknown[]; limit: number };
    assert.ok(body.limit <= 200, \`the page size must be capped (got \${body.limit})\`);
    assert.ok(body.records.length <= 200, 'no more than one capped page of records is returned');
  });`,
  });

  tests.push({
    name: `V8.2.3 ${name}: people only see the fields they are allowed to see`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.3',
      proves: 'A reply contains only the fields of the form plus the record’s own details — never a raw database column or another person’s identifier.',
    },
    code: `  test('V8.2.3 ${name}: people only see the fields they are allowed to see', async () => {
    const jar = await app.login(${signIn});
    const created = await app.json('POST', API, PAYLOAD_A, jar);
    const record = (await created.json()) as Record<string, unknown> & { id: string };
    assert.equal(created.status, 201);
    const extra = Object.keys(record).filter((k) => !OWNER_FIELDS.has(k)${plan.adminOnly ? " && k !== 'ownerId'" : ''});
    assert.deepEqual(extra, [], 'the response must contain only form fields and record metadata (no raw columns or owner ids)');
${
  plan.adminOnly
    ? ''
    : `
    const admin = await app.login(users.admin);
    const read = await app.fetch(\`\${API}/\${record.id}\`, { jar: admin, headers: { Accept: 'application/json' } });
    const adminView = read.status === 200 ? ((await read.json()) as Record<string, unknown>) : (await read.text(), undefined);
    if (adminView) {
      const adminExtra = Object.keys(adminView).filter((k) => !OWNER_FIELDS.has(k) && k !== 'ownerId');
      assert.deepEqual(adminExtra, [], 'the administrator view adds only the owner id');
    }`
}
  });`,
  });

  if (plan.ownerScoped) {
    tests.push({
      name: `V8.2.2 ${name}: changing the id in the address to a record owned by someone else is refused`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.2',
        proves: `Guessing the address of someone else’s ${plan.entity.label.toLowerCase()} does not open it: reading, changing and deleting are all refused.`,
      },
      code: `  test('V8.2.2 ${name}: changing the id in the address to a record owned by someone else is refused', async () => {
    const owner = await app.login(users.member);
    const created = await app.json('POST', API, PAYLOAD_A, owner);
    const record = (await created.json()) as { id: string; updatedAt: string };
    assert.equal(created.status, 201);

    const other = await app.login(users.member2);
    const read = await app.fetch(\`\${API}/\${record.id}\`, { jar: other });
    await read.text();
    assert.ok(read.status === 403 || read.status === 404, \`a non-owner must not read the record (got \${read.status})\`);

    const write = await app.json('PATCH', \`\${API}/\${record.id}\`, { ...PAYLOAD_B, updatedAt: record.updatedAt }, other);
    await write.text();
    assert.ok(write.status === 403 || write.status === 404, \`a non-owner must not change the record (got \${write.status})\`);

    const remove = await app.json('DELETE', \`\${API}/\${record.id}\`, undefined, other);
    await remove.text();
    assert.ok(remove.status === 403 || remove.status === 404, \`a non-owner must not delete the record (got \${remove.status})\`);
  });`,
    });
  }

  if (plan.adminOnly) {
    tests.push({
      name: `V8.3.1 ${name}: permission checks happen on the server, so the action is refused without the administrator role`,
      requirement: {
        standard: 'asvs',
        id: 'V8.3.1',
        proves: 'The role check happens on the server: a signed-in person without the administrator role is refused even when they call the interface directly.',
      },
      code: `  test('V8.3.1 ${name}: permission checks happen on the server, so the action is refused without the administrator role', async () => {
    const member = await app.login(users.member);
    const res = await app.fetch(API, { jar: member });
    await res.text();
    assert.ok(res.status === 403 || res.status === 404, \`a non-administrator must be refused (got \${res.status})\`);
  });`,
    });
  }

  if (sensitive.length > 0) {
    tests.push({
      name: `V8.2.3 ${name}: sensitive fields are not among the fields other people are shown`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.3',
        proves: `The sensitive fields of a ${plan.entity.label.toLowerCase()} (${sensitive.map((f) => f.field.label).join(', ')}) appear for the owner and are left out of what other people are shown.`,
      },
      code: `  test('V8.2.3 ${name}: sensitive fields are not among the fields other people are shown', async () => {
    const owner = await app.login(users.member);
    const created = await app.json('POST', API, PAYLOAD_A, owner);
    const record = (await created.json()) as Record<string, unknown> & { id: string };
    assert.equal(created.status, 201);
${sensitive.map((f) => `    assert.ok(${JSON.stringify(f.prop)} in record, 'the owner sees ${f.field.label}');`).join('\n')}

    const list = await app.fetch(API, { jar: await app.login(users.member2) });
    const body = (await list.json()) as { records?: Record<string, unknown>[] };
    for (const r of body.records ?? []) {
${sensitive.map((f) => `      assert.ok(!(${JSON.stringify(f.prop)} in r), '${f.field.label} must not be listed for other people');`).join('\n')}
    }
  });`,
    });
  }

  return tests;
}

/** The requirement mapping for one record type: every emitted test that says what it evidences. */
export function recordTypeRequirements(plan: EntityPlan): RecipeRequirement[] {
  return recordTypeTests(plan)
    .filter((t): t is EmittedTest & { requirement: NonNullable<EmittedTest['requirement']> } => t.requirement !== undefined)
    .map((t) => ({ ...t.requirement, test: t.name }));
}

/**
 * A complete, valid body for creating or updating one record, as source text. The attachment recipe uses it too,
 * so its tests can create a record to attach a file to without restating the record's shape.
 */
export function payloadLiteral(plan: EntityPlan, variant: 'a' | 'b', indent = '  '): string {
  const lines = plan.fields.map((f) => `${indent}${f.prop}: ${sampleValue(f, variant)},`);
  return `{\n${lines.join('\n')}\n${indent.slice(0, -2)}}`;
}

export function emitTest(plan: EntityPlan, runId: string): string {
  const label = plan.entity.label;
  const payloadA = plan.fields.map((f) => `  ${f.prop}: ${sampleValue(f, 'a')},`).join('\n');
  const payloadB = plan.fields.map((f) => `  ${f.prop}: ${sampleValue(f, 'b')},`).join('\n');

  return `// Generated by SecureVibe (recipe record-type) — run ${runId}
/** ${label}: the security checks every generated feature must pass (SC-17). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, startApp, type RunningApp } from '../helpers/app.ts';
import { users } from '../helpers/conventions.ts';

const BASE = '${plan.base}';
const API = '/api${plan.base}';

const PAYLOAD_A = {
${payloadA}
};
const PAYLOAD_B = {
${payloadB}
};
/** Everything the owner view may contain: the form fields plus record metadata. */
const OWNER_FIELDS = new Set([${plan.fields.map((f) => JSON.stringify(f.prop)).join(', ')}${plan.fields.length > 0 ? ', ' : ''}'id', 'createdAt', 'updatedAt']);

describe('${plan.entity.name}', () => {
  let app: RunningApp;
  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

${recordTypeTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
