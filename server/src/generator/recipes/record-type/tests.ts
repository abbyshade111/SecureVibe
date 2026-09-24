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
import { commentText } from '../js-literal.js';
import type { EntityPlan, FieldPlan } from './fields.js';
import { queryPlanOf, type QueryPlan } from './query.js';

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

  tests.push(...queryTests(plan, queryPlanOf(plan)));

  return tests;
}

/** The requirement mapping for one record type: every emitted test that says what it evidences. */
/**
 * Tests for the list's search, sort, filter and paging.
 *
 * The one that matters is V8.2.2. A list that forgets its ownership clause looks perfectly normal, and the way it
 * usually gets forgotten is that somebody adds search. So the test does not check that search works; it checks that
 * search cannot be used to reach a record belonging to somebody else, by searching for the exact text of one.
 */
function queryTests(plan: EntityPlan, query: QueryPlan): EmittedTest[] {
  const name = plan.entity.name;
  const tests: EmittedTest[] = [];
  const signIn = plan.adminOnly ? 'users.admin' : 'users.member';
  // Free text only. A searchable column may be an email address or a web address, and neither will accept an
  // arbitrary word — the earlier version fell back to creating a plain record when the write was refused, which
  // made the search find nothing for anybody and the assertion pass whatever the app did. A test that cannot fail
  // is worse than no test, so the field is chosen so the write must succeed, and the test proves the term really
  // matches before it proves it does not leak.
  const freeText = new Set(plan.fields.filter((f) => f.control === 'text' || f.control === 'textarea').map((f) => f.column));
  const searchField = query.searchable.find((c) => freeText.has(c.column));

  tests.push({
    name: `V1.2.4 ${name}: what a person types reaches the database as a bound value, never as part of the query, so an injection attempt is only ever text`,
    requirement: {
      standard: 'asvs',
      id: 'V1.2.4',
      proves:
        'Search terms, sort names, directions and filter values that look like SQL are treated as text or refused: the table is still there afterwards, the records are unchanged, and nothing a person typed became part of a statement.',
    },
    code: `  test('V1.2.4 ${name}: what a person types reaches the database as a bound value, never as part of the query, so an injection attempt is only ever text', async () => {
    const jar = await app.login(${signIn});
    await createOne(jar);
    const before = await countList(jar);
    assert.ok(before >= 1, 'there must be something to lose before we try to lose it');

    // Each of these is a real attempt, not a lookalike: a comment, a quote break, a dropped table, a tautology.
    const attempts = [
      '?search=%25',
      "?search=' OR '1'='1",
      "?search=x'); DROP TABLE ${plan.table}; --",
      '?sort=id; DROP TABLE ${plan.table}',
      '?sort=(SELECT 1)',
      '?direction=asc, id',
      '?search=' + encodeURIComponent('_'),
    ];
    for (const attempt of attempts) {
      const res = await app.fetch(\`\${API}\${attempt}\`, { jar });
      const body = await res.text();
      // Refused or answered, both are fine. Answering with somebody else's data, or a 500, is not.
      assert.ok(res.status === 200 || res.status === 400, \`\${attempt} answered \${res.status}: \${body.slice(0, 120)}\`);
    }

    // The table is still there and still holds what it held.
    const after = await countList(jar);
    assert.equal(after, before, 'no attempt may add or remove a record');
    const plain = await app.json('GET', API, undefined, jar);
    assert.equal(plain.status, 200, 'the list must still work afterwards');
    await plain.text();
  });`,
  });

  tests.push({
    name: `V2.2.1 ${name}: a way of ordering or narrowing the list that it does not offer is checked against what is expected before the app uses it`,
    requirement: {
      standard: 'asvs',
      id: 'V2.2.1',
      proves:
        'The list only accepts the questions it offers: a key it does not know is refused, and a sort column or direction outside its allow-list is ignored with a sentence saying so rather than reaching the query.',
    },
    code: `  test('V2.2.1 ${name}: a way of ordering or narrowing the list that it does not offer is checked against what is expected before the app uses it', async () => {
    const jar = await app.login(${signIn});
    // A key the list does not have is refused outright, because the schema names every one it accepts.
    for (const query of ['?nonsense=1', '?owner_id=someone-else', '?direction=sideways']) {
      const res = await app.fetch(\`\${API}\${query}\`, { jar });
      await res.text();
      assert.equal(res.status, 400, \`\${query} must be refused (got \${res.status})\`);
    }
    // A sort column that exists as a key but is not one this list offers is ignored, and the list still answers.
    const res = await app.json('GET', \`\${API}?sort=owner_id\`, undefined, jar);
    const body = (await res.json()) as { ignored?: string[]; sort?: string };
    assert.equal(res.status, 200, 'an impossible sort must not break the list');
    assert.notEqual(body.sort, 'owner_id', 'the list must not sort by a column it does not offer');
    assert.ok((body.ignored ?? []).length > 0, 'and it must say that it did something else');
  });`,
  });

  if (plan.ownerScoped && searchField) {
    tests.push({
      name: `V8.2.2 ${name}: searching and sorting cannot reach another person\u2019s data, because the ownership clause is part of every query`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.2',
        proves: `Searching for the exact text of somebody else's ${plan.entity.label.toLowerCase()} returns nothing, and neither does sorting or paging past it: the scope is chosen from how the record type was described, not by the code calling the list.`,
      },
      // The value searched for is the other person's own, so a scope that has been dropped shows up immediately.
      code: `  test('V8.2.2 ${name}: searching and sorting cannot reach another person${'\u2019'}s data, because the ownership clause is part of every query', async () => {
    const theirs = await app.login(users.member2);
    // randomUUID rather than Math.random: the static scan objects to Math.random in generated code, and it is
    // right to, because the next person to copy this line may be using it for something that must be unguessable.
    const secret = 'zzq-' + randomUUID().slice(0, 8);
    const created = await app.json('POST', API, { ...PAYLOAD_A, ${JSON.stringify(searchField.prop)}: secret }, theirs);
    await created.text();
    assert.equal(created.status, 201, 'the other person must be able to create the record this test searches for');

    // Their own search must find it. Without this the next assertion passes when the term matches nothing at all,
    // which it would do just as happily if the ownership clause had been dropped.
    const theirHits = await searchIds(theirs, secret);
    assert.ok(theirHits.length > 0, 'the search term must match their own record, or this test proves nothing');

    const mine = await app.login(users.member);
    for (const query of ['?search=' + encodeURIComponent(secret), '?search=' + encodeURIComponent(secret) + '&sort=${searchField.column}', '?page=1', '?page=2']) {
      const res = await app.json('GET', \`\${API}\${query}\`, undefined, mine);
      const body = (await res.json()) as { records?: { id: string }[] };
      assert.equal(res.status, 200, \`\${query} must answer\`);
      for (const record of body.records ?? []) {
        assert.ok(!JSON.stringify(record).includes(secret), \`\${query} returned another person's record\`);
      }
    }
  });`,
    });
  }

  if (searchField) {
    tests.push({
      name: `${name}: searching narrows the list to what matches, and clearing it brings the rest back`,
      code: `  test('${name}: searching narrows the list to what matches, and clearing it brings the rest back', async () => {
    const jar = await app.login(${signIn});
    const all = await countList(jar);
    const absent = await app.json('GET', \`\${API}?search=\${encodeURIComponent('zzq-nothing-has-this')}\`, undefined, jar);
    const body = (await absent.json()) as { records: unknown[]; total?: number };
    assert.equal(absent.status, 200);
    assert.equal(body.records.length, 0, 'a search for something absent must match nothing');
    // Measured as a change rather than against a number: test mode seeds a record of its own.
    assert.equal(await countList(jar), all, 'clearing the search brings the list back to what it was');
  });`,
    });
  }

  return tests;
}

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
/** ${commentText(label)}: the security checks every generated feature must pass (SC-17). */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
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

  /** One ${commentText(plan.entity.label.toLowerCase())}, through its own interface. */
  async function createOne(jar: CookieJar): Promise<void> {
    const res = await app.json('POST', API, PAYLOAD_A, jar);
    await res.text();
    assert.equal(res.status, 201, \`a ${plan.entity.label.toLowerCase()} must be created (got \${res.status})\`);
  }

  /** The ids a search turns up for one person. */
  async function searchIds(jar: CookieJar, term: string): Promise<string[]> {
    const res = await app.json('GET', \`\${API}?search=\${encodeURIComponent(term)}\`, undefined, jar);
    const body = (await res.json()) as { records?: { id: string }[] };
    assert.equal(res.status, 200, \`a search must answer (got \${res.status})\`);
    return (body.records ?? []).map((r) => r.id);
  }

  /** How many the list says there are. Read from the list rather than counted in the test. */
  async function countList(jar: CookieJar, query = ''): Promise<number> {
    const res = await app.json('GET', \`\${API}\${query}\`, undefined, jar);
    const body = (await res.json()) as { total?: number; records?: unknown[] };
    assert.equal(res.status, 200, \`the list must answer (got \${res.status})\`);
    return body.total ?? (body.records ?? []).length;
  }

${recordTypeTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
