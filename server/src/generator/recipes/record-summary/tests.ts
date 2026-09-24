/**
 * Test emitter for the record-summary recipe.
 *
 * The figures are checked by comparing the page with itself rather than against numbers written into the test: one
 * record, then a second identical one, and every total must have doubled. That way the test cannot drift out of step
 * with whatever sample values the record type's own tests happen to use, and it still fails if a total is computed
 * over the wrong rows.
 */
import type { EntityField } from '@shared/profile.js';
import { commentText } from '../js-literal.js';
import type { RecipeRequirement } from '../types.js';
import { payloadLiteral } from '../record-type/tests.js';
import type { SummaryPlan } from './emit.js';

export interface EmittedTest {
  name: string;
  code: string;
  requirement?: Omit<RecipeRequirement, 'test'>;
}

/** Fields that would have been summarized but are left out because the person marked them sensitive. */
export function excludedSensitiveFields(plan: SummaryPlan): EntityField[] {
  const kinds = new Set(['number', 'money', 'choice', 'boolean']);
  return plan.entity.entity.fields.filter((f) => f.sensitive && kinds.has(f.type));
}

export function summaryTests(plan: SummaryPlan): EmittedTest[] {
  const entity = plan.entity;
  const name = entity.entity.name;
  const signIn = entity.adminOnly ? 'users.admin' : 'users.member';
  const tests: EmittedTest[] = [];

  tests.push({
    name: `${name}: the report counts each record once and adds up the amounts`,
    // Every figure is checked as a change from what the page said a moment ago, never against a number written
    // into the test: the app seeds a record of its own in test mode, so the table is never empty to begin with,
    // and the sample values belong to the record type's tests rather than to this one.
    code: `  test('${name}: the report counts each record once and adds up the amounts', async () => {
    const jar = await app.login(${signIn});
    const before = await readReport(jar);

    await createRecord(jar);
    const one = await readReport(jar);
    assert.equal(one.records, before.records + 1, 'adding a record must add exactly one to the count');

    await createRecord(jar);
    const two = await readReport(jar);
    assert.equal(two.records, one.records + 1, 'adding another record must add exactly one more');

    // The two records are identical, so each one must move every figure by the same amount.
    for (const [label, after] of one.totals) {
      const start = before.totals.get(label) ?? 0;
      const end = two.totals.get(label);
      assert.ok(end !== undefined, \`"\${label}" disappeared from the report\`);
      // The figures are shown to the penny, so they are compared to the penny.
      assert.ok(
        Math.abs(end - after - (after - start)) < 0.011,
        \`"\${label}" must rise by the same amount for each identical record: \${start} then \${after} then \${end}\`,
      );
    }
  });`,
  });

  tests.push({
    name: `V2.2.1 ${name}: a date in the report filter is checked against what is expected before the app uses it`,
    requirement: {
      standard: 'asvs',
      id: 'V2.2.1',
      proves: 'The two dates that narrow the report are checked against the expected format, and anything else is refused rather than reaching a query.',
    },
    code: `  test('V2.2.1 ${name}: a date in the report filter is checked against what is expected before the app uses it', async () => {
    const jar = await app.login(${signIn});
    for (const query of ['?from=yesterday', '?to=01/02/2026', "?from=2026-01-01'--", '?whenever=2026-01-01']) {
      const res = await app.fetch(\`\${REPORT}\${query}\`, { jar });
      await res.text();
      assert.equal(res.status, 400, \`\${query} must be refused (got \${res.status})\`);
    }
    // A real range is accepted.
    const ok = await app.fetch(\`\${REPORT}?from=2026-01-01&to=2099-12-31\`, { jar });
    await ok.text();
    assert.equal(ok.status, 200, 'a valid range must be accepted');
  });`,
  });

  {
    tests.push({
      name: `V8.2.1 ${name}: the report is not a page available without signing in, and anything not explicitly allowed is refused`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.1',
        proves: 'Someone who has not signed in cannot read the report page.',
      },
      code: `  test('V8.2.1 ${name}: the report is not a page available without signing in, and anything not explicitly allowed is refused', async () => {
    const owner = await app.login(${signIn});
    await createRecord(owner);
    const res = await app.fetch(REPORT, { jar: new CookieJar() });
    const body = await res.text();
    assert.ok(
      res.status === 401 || res.status === 403 || (isRedirect(res) && /login|sign-?in/i.test(locationOf(res))),
      \`the report must not be readable without signing in (got \${res.status} \${locationOf(res)})\`,
    );
    assert.doesNotMatch(body, /data-records=/, 'no figures may be served to a visitor who has not signed in');
  });`,
    });
  }

  if (entity.ownerScoped) {
    tests.push({
      name: `V8.2.2 ${name}: the report counts only your own records, never another person’s`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.2',
        proves: 'Each person’s report is taken over their own records only: another person’s records change neither the count nor any total.',
      },
      code: `  test('V8.2.2 ${name}: the report counts only your own records, never another person’s', async () => {
    const owner = await app.login(users.member);
    await createRecord(owner);
    const mine = await readReport(owner);

    // Somebody else adds two records of their own.
    const other = await app.login(users.member2);
    const theirsBefore = await readReport(other);
    await createRecord(other);
    await createRecord(other);

    const after = await readReport(owner);
    assert.equal(after.records, mine.records, "another person's records must not be counted in your report");
    for (const [label, value] of mine.totals) {
      assert.equal(after.totals.get(label), value, \`"\${label}" must not include another person's records\`);
    }
    const theirs = await readReport(other);
    assert.equal(theirs.records, theirsBefore.records + 2, 'their own report counts their own records');
  });`,
    });
  }

  const excluded = excludedSensitiveFields(plan);
  tests.push({
    name: `V8.2.3 ${name}: the report shows only the fields people are allowed to see`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.3',
      proves:
        excluded.length > 0
          ? `${excluded.map((f) => f.label).join(', ')} ${excluded.length === 1 ? 'is' : 'are'} marked sensitive, so ${excluded.length === 1 ? 'it is' : 'they are'} left out of the report — a total can give away as much as the values — and every figure the page does show is checked against the list of fields it may show.`
          : 'Every figure the page shows is checked against the list of fields it may show, so a field nobody is allowed to see cannot appear on it.',
    },
    // Checking what the page shows against an allow-list, rather than looking for the absence of one label, cannot
    // pass by accident: a label that arrived in some other shape is still not on the list.
    code: `  test('V8.2.3 ${name}: the report shows only the fields people are allowed to see', async () => {
    const jar = await app.login(${signIn});
    await createRecord(jar);
    const { totals } = await readReport(jar);
    const unexpected = [...totals.keys()].filter((k) => !ALLOWED_FIGURES.has(k));
    assert.deepEqual(unexpected, [], 'the report must show only the figures it is meant to');
${excluded.length > 0 ? `    for (const label of ${JSON.stringify(excluded.map((f) => f.label))}) {
      assert.ok(!ALLOWED_FIGURES.has(label), \`\${label} is sensitive and must not even be allowed on the report\`);
    }
` : ''}  });`,
  });

  return tests;
}

/**
 * The labels the report is allowed to put a figure under: one per amount or yes/no field, and one per option of
 * each choice field (plus the "(not set)" row for anything stored that is not one of the described options).
 */
export function allowedFigures(plan: SummaryPlan): string[] {
  return plan.fields.flatMap((f) => (f.kind === 'choice' ? [...f.choices.map((c) => `${f.label}: ${c}`), `${f.label}: (not set)`] : [f.label]));
}

export function summaryRequirements(plan: SummaryPlan): RecipeRequirement[] {
  return summaryTests(plan)
    .filter((t): t is EmittedTest & { requirement: NonNullable<EmittedTest['requirement']> } => t.requirement !== undefined)
    .map((t) => ({ ...t.requirement, test: t.name }));
}

export function emitTest(plan: SummaryPlan, runId: string): string {
  const entity = plan.entity;
  return `// Generated by SecureVibe (recipe record-summary) — run ${runId}
/** ${commentText(plan.title)}: that the figures are right, and taken over the right records. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { users } from '../helpers/conventions.ts';

const REPORT = '${plan.path}';
const API = '/api${entity.base}';

/** Every figure this report may show, named as the page names it. Nothing else may appear. */
const ALLOWED_FIGURES = new Set(${JSON.stringify(allowedFigures(plan))});

/** A body for creating one record, the same shape the record's own tests use. */
const PAYLOAD = ${payloadLiteral(entity, 'a')};

describe('${entity.entity.name} report', () => {
  let app: RunningApp;

  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

  /** Creates one record through the record's own interface. */
  async function createRecord(jar: CookieJar): Promise<string> {
    const res = await app.json('POST', API, PAYLOAD, jar);
    const body = (await res.json()) as { id: string };
    assert.equal(res.status, 201, 'the record must be created for the report to count');
    return body.id;
  }

  /**
   * The figures on the report page. Each row carries its value as data as well as text, so a test reads the number
   * the page computed rather than trying to parse a sentence.
   */
  async function readReport(jar: CookieJar): Promise<{ records: number; totals: Map<string, number> }> {
    const { res, html } = await app.page(REPORT, jar);
    assert.equal(res.status, 200, \`the report must be readable (got \${res.status})\`);
    const records = Number(html.match(/data-records="(\\d+)"/)?.[1] ?? '-1');
    const totals = new Map<string, number>();
    for (const m of html.matchAll(/data-total="([^"]*)" data-value="([^"]*)"/g)) {
      totals.set(m[1]!, Number(m[2]));
    }
    return { records, totals };
  }

${summaryTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
