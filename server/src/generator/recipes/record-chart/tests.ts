/**
 * Test emitter for the record-chart recipe.
 *
 * The figures are checked the same way the report's are: by comparing the page with itself. Test-bootstrap mode
 * seeds a record of its own, and the app has been running for however long, so nothing here may assume a month
 * starts at zero. Adding a record must raise this month's figure by exactly one, and every amount by exactly what
 * that record carries — measured as a change, never against a number written into the test.
 *
 * One test is about the drawing rather than the figures: a chart is the one page in a generated app that writes
 * numbers straight into markup, so there is a test that every value in it really is a number and that no text
 * anybody typed reaches it.
 */
import type { EntityField } from '@shared/profile.js';
import { commentText, jsString } from '../js-literal.js';
import type { RecipeRequirement } from '../types.js';

import { payloadLiteral } from '../record-type/tests.js';
import type { ChartPlan } from './emit.js';

export interface EmittedTest {
  name: string;
  code: string;
  requirement?: Omit<RecipeRequirement, 'test'>;
}

/** Amount fields the chart would have drawn but leaves out because the person marked them sensitive. */
export function excludedSensitiveAmounts(plan: ChartPlan): EntityField[] {
  return plan.entity.entity.fields.filter((f) => f.sensitive && (f.type === 'number' || f.type === 'money'));
}

/**
 * A field the test can type markup into. The chart draws no text from a record, and this is how that is shown: a
 * record whose text looks like markup, then a chart page that contains neither the markup nor the text.
 */
export function typedTextField(plan: ChartPlan): { prop: string; label: string } | undefined {
  const field = plan.entity.fields.find((f) => f.control === 'text' || f.control === 'textarea');
  return field ? { prop: field.prop, label: field.field.label } : undefined;
}

export function chartTests(plan: ChartPlan): EmittedTest[] {
  const entity = plan.entity;
  const name = entity.entity.name;
  const signIn = entity.adminOnly ? 'users.admin' : 'users.member';
  const typed = typedTextField(plan);
  const tests: EmittedTest[] = [];

  tests.push({
    name: `${name}: adding a record raises this month\u2019s figures by exactly what that record carries`,
    code: `  test('${name}: adding a record raises this month${'’'}s figures by exactly what that record carries', async () => {
    const jar = await app.login(${signIn});
    const before = await readChart(jar);
    const month = thisMonth();
    const countKey = \`\${CHART_SERIES[0]}|\${month}\`;
    assert.ok(before.has(countKey), 'the chart must have a bar for the month we are in');

    await createRecord(jar);
    const one = await readChart(jar);
    await createRecord(jar);
    const two = await readChart(jar);

    // The two records are identical, so each must move every figure for this month by the same amount.
    for (const series of CHART_SERIES) {
      const key = \`\${series}|\${month}\`;
      const start = before.get(key) ?? 0;
      const middle = one.get(key);
      const end = two.get(key);
      assert.ok(middle !== undefined && end !== undefined, \`"\${series}" lost its bar for \${month}\`);
      // The figures are shown to the penny, so they are compared to the penny.
      assert.ok(
        Math.abs(end - middle - (middle - start)) < 0.011,
        \`"\${series}" must rise by the same amount for each identical record: \${start} then \${middle} then \${end}\`,
      );
    }
    assert.equal(one.get(countKey), (before.get(countKey) ?? 0) + 1, 'one new record must add exactly one to the count for this month');
  });`,
  });

  tests.push({
    name: `V2.2.1 ${name}: the number of months asked for is checked against what is expected before the app uses it`,
    requirement: {
      standard: 'asvs',
      id: 'V2.2.1',
      proves: 'The one thing the chart takes from the address bar, how many months to draw, is checked against the expected range and anything else is refused rather than reaching a query or the drawing.',
    },
    code: `  test('V2.2.1 ${name}: the number of months asked for is checked against what is expected before the app uses it', async () => {
    const jar = await app.login(${signIn});
    for (const query of ['?months=0', '?months=37', '?months=-6', '?months=1e3', '?months=all', '?months=6.5', '?year=2026']) {
      const res = await app.fetch(\`\${CHART}\${query}\`, { jar });
      await res.text();
      assert.equal(res.status, 400, \`\${query} must be refused (got \${res.status})\`);
    }
    const ok = await app.fetch(\`\${CHART}?months=6\`, { jar });
    const html = await ok.text();
    assert.equal(ok.status, 200, 'a number of months within the limits must be accepted');
    assert.equal([...html.matchAll(/data-month="/g)].length, 6 * CHART_SERIES.length, 'six months must draw six bars in each picture');
  });`,
  });

  tests.push({
    name: `V8.2.1 ${name}: the chart is not a page available without signing in, and anything not explicitly allowed is refused`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.1',
      proves: 'Someone who has not signed in cannot open the chart page or read any figure from it.',
    },
    code: `  test('V8.2.1 ${name}: the chart is not a page available without signing in, and anything not explicitly allowed is refused', async () => {
    const owner = await app.login(${signIn});
    await createRecord(owner);
    const res = await app.fetch(CHART, { jar: new CookieJar() });
    const body = await res.text();
    assert.ok(
      res.status === 401 || res.status === 403 || (isRedirect(res) && /login|sign-?in/i.test(locationOf(res))),
      \`the chart must not be readable without signing in (got \${res.status} \${locationOf(res)})\`,
    );
    assert.doesNotMatch(body, /data-month=/, 'no figures may be served to a visitor who has not signed in');
  });`,
  });

  if (entity.ownerScoped) {
    tests.push({
      name: `V8.2.2 ${name}: the chart is drawn from only your own records, never another person’s`,
      requirement: {
        standard: 'asvs',
        id: 'V8.2.2',
        proves: 'Each person’s chart is drawn from their own records only: another person’s records change no bar on it.',
      },
      code: `  test('V8.2.2 ${name}: the chart is drawn from only your own records, never another person${'’'}s', async () => {
    const owner = await app.login(users.member);
    await createRecord(owner);
    const mine = await readChart(owner);

    // Somebody else adds two records of their own.
    const other = await app.login(users.member2);
    const theirsBefore = await readChart(other);
    await createRecord(other);
    await createRecord(other);

    const after = await readChart(owner);
    for (const [key, value] of mine) {
      assert.equal(after.get(key), value, \`"\${key}" must not include another person's records\`);
    }
    const month = thisMonth();
    const countKey = \`\${CHART_SERIES[0]}|\${month}\`;
    assert.equal(
      (await readChart(other)).get(countKey),
      (theirsBefore.get(countKey) ?? 0) + 2,
      'their own chart is drawn from their own records',
    );
  });`,
    });
  }

  const excluded = excludedSensitiveAmounts(plan);
  tests.push({
    name: `V8.2.3 ${name}: the chart shows only the figures people are allowed to see`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.3',
      proves:
        excluded.length > 0
          ? `${excluded.map((f) => f.label).join(', ')} ${excluded.length === 1 ? 'is' : 'are'} marked sensitive, so ${excluded.length === 1 ? 'it is' : 'they are'} not drawn — a month by month total can give away as much as the values — and every figure the chart does draw is checked against the list of figures it may draw.`
          : 'Every figure the chart draws is checked against the list of figures it may draw, so a field nobody is allowed to see cannot appear on it.',
    },
    code: `  test('V8.2.3 ${name}: the chart shows only the figures people are allowed to see', async () => {
    const jar = await app.login(${signIn});
    await createRecord(jar);
    const { html } = await app.page(CHART, jar);
    const drawn = new Set([...html.matchAll(/data-series="([^"]*)"/g)].map((m) => m[1]!));
    assert.deepEqual([...drawn].filter((s) => !ALLOWED_FIGURES.has(s)), [], 'the chart must draw only the figures it is meant to');
${
  excluded.length > 0
    ? `    for (const label of ${JSON.stringify(excluded.map((f) => f.label))}) {
      assert.ok(![...ALLOWED_FIGURES].some((s) => s.toLowerCase().includes(label.toLowerCase())), \`\${label} is sensitive and must not even be allowed on the chart\`);
    }
`
    : ''
}  });`,
  });

  // The chart is the one page that writes numbers straight into markup, so this is where that is checked. Without a
  // free-text field on the record type there is nothing to type markup into, so the test still checks the drawing
  // but no longer stands as evidence for the encoding requirement.
  const encodingName = typed
    ? `V1.2.1 ${name}: every value in the chart drawing is a number in an html attribute, and text a person typed is never drawn`
    : `${name}: every value in the chart drawing is a number`;
  tests.push({
    name: encodingName,
    ...(typed
      ? {
          requirement: {
            standard: 'asvs' as const,
            id: 'V1.2.1',
            proves: `Every value the chart writes into the html attributes it draws with is a plain number, and a record whose ${typed.label.toLowerCase()} is typed as markup appears nowhere on the chart page — neither as markup nor as text — because no text from a record is drawn at all.`,
          },
        }
      : {}),
    code: `  test(${jsString(encodingName)}, async () => {
    const jar = await app.login(${signIn});
${typed ? `    await app.json('POST', API, { ...PAYLOAD, ${typed.prop}: TYPED_AS_MARKUP }, jar);\n` : `    await createRecord(jar);\n`}    const { res, html } = await app.page(CHART, jar);
    assert.equal(res.status, 200, 'the chart must be readable');

    // Everything the drawing positions or sizes itself with must be a number and nothing else.
    const drawing = html.slice(html.indexOf('<svg'), html.indexOf('</svg>') + 6);
    assert.ok(drawing.length > 0, 'the page must contain a drawing');
    const numeric = [...drawing.matchAll(/\\s(?:x|y|x1|y1|x2|y2|width|height|font-size|opacity|stroke-width)="([^"]*)"/g)].map((m) => m[1]!);
    assert.ok(numeric.length > 0, 'the drawing must carry the values it is drawn from');
    const notNumbers = numeric.filter((v) => !/^-?\\d+(?:\\.\\d+)?$/.test(v) && v !== '100%');
    assert.deepEqual(notNumbers, [], 'every value the drawing is made of must be a number');

    // And no markup of its own: the drawing is shapes and the app's own labels, never a script or a style.
    assert.doesNotMatch(drawing, /<script|<style|<foreignObject|\\son[a-z]+=/i, 'the drawing must contain nothing that runs');
${typed ? `
    // Nothing a person typed is drawn, so text that looks like markup cannot arrive as markup or as text.
    assert.ok(!html.includes(TYPED_AS_MARKUP), 'text a person typed must not appear on the chart page');
    assert.doesNotMatch(html, /alert\\(1\\)/, 'text a person typed must not reach the page as something that runs');
` : ''}  });`,
  });

  return tests;
}

/** The labels the chart is allowed to draw a figure under: the count, and one per amount it may total. */
export function allowedFigures(plan: ChartPlan): string[] {
  return plan.series.map((s) => s.label);
}

export function chartRequirements(plan: ChartPlan): RecipeRequirement[] {
  return chartTests(plan)
    .filter((t): t is EmittedTest & { requirement: NonNullable<EmittedTest['requirement']> } => t.requirement !== undefined)
    .map((t) => ({ ...t.requirement, test: t.name }));
}

export function emitTest(plan: ChartPlan, runId: string): string {
  const entity = plan.entity;
  const typed = typedTextField(plan);
  return `// Generated by SecureVibe (recipe record-chart) — run ${runId}
/** ${commentText(plan.title)}: that the figures are right, drawn from the right records, and made only of numbers. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { users } from '../helpers/conventions.ts';

const CHART = '${plan.path}';
const API = '/api${entity.base}';

/** Every figure this chart may draw, named as the page names it. Nothing else may appear. */
const ALLOWED_FIGURES = new Set(${JSON.stringify(allowedFigures(plan))});
/** In the order the page draws them, which is how a test finds the count series. */
const CHART_SERIES = ${JSON.stringify(allowedFigures(plan))};

/** A body for creating one record, the same shape the record's own tests use. */
const PAYLOAD = ${payloadLiteral(entity, 'a')};
${typed ? `\n/** Text that would be markup if anything ever drew it. Nothing on the chart page may contain it. */\nconst TYPED_AS_MARKUP = '</text><script>alert(1)</script>';\n` : ''}
/** The month the test is running in, as the chart labels it. */
function thisMonth(): string {
  const now = new Date();
  return \`\${now.getUTCFullYear()}-\${String(now.getUTCMonth() + 1).padStart(2, '0')}\`;
}

describe('${entity.entity.name} chart', () => {
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
    assert.equal(res.status, 201, 'the record must be created for the chart to draw it');
    return body.id;
  }

  /**
   * Every figure on the chart page, keyed "series|month". The table under each picture carries the same numbers the
   * bars are drawn from, so a test reads the figure the page computed rather than measuring a rectangle.
   */
  async function readChart(jar: CookieJar): Promise<Map<string, number>> {
    const { res, html } = await app.page(CHART, jar);
    assert.equal(res.status, 200, \`the chart must be readable (got \${res.status})\`);
    const figures = new Map<string, number>();
    for (const m of html.matchAll(/data-series="([^"]*)" data-month="([^"]*)" data-value="([^"]*)"/g)) {
      figures.set(\`\${m[1]}|\${m[2]}\`, Number(m[3]));
    }
    return figures;
  }

${chartTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
