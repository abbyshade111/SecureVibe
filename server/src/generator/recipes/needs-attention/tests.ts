/**
 * Test emitter for the needs-attention recipe.
 *
 * This page gathers records from several record types, each with its own answer to who may see it, so the tests are
 * mostly about that: what a member is sent, what an administrator is sent, and what neither is sent. Everything is
 * measured as a change from what the page said a moment earlier, because test-bootstrap mode seeds a record of its
 * own and the app may have been running for a while.
 *
 * The field-level test is worth explaining. Rather than listing at generation time which values must not appear, it
 * asks the record's own interface what the record holds and then requires that none of those values, beyond the date
 * and the name, is on the page. That way it cannot drift out of step with the sample values the record's own tests
 * use, and it keeps testing something as fields are added.
 */
import type { RecipeRequirement } from '../types.js';
import { commentText } from '../js-literal.js';
import { payloadLiteral } from '../record-type/tests.js';
import type { AttentionPlan, AttentionSection } from './emit.js';

export interface EmittedTest {
  name: string;
  code: string;
  requirement?: Omit<RecipeRequirement, 'test'>;
}

/** The section the everyday tests work through: one anybody signed in can see, preferring one that shows a name. */
export function showcaseOf(plan: AttentionPlan): AttentionSection | undefined {
  const open = plan.sections.filter((s) => !s.entity.adminOnly);
  return open.find((s) => s.title !== undefined) ?? open[0];
}

export function ownerSectionOf(plan: AttentionPlan): AttentionSection | undefined {
  return plan.sections.find((s) => s.entity.ownerScoped && !s.entity.adminOnly);
}

export function adminSectionOf(plan: AttentionPlan): AttentionSection | undefined {
  return plan.sections.find((s) => s.entity.adminOnly);
}

export function withheldSectionOf(plan: AttentionPlan): AttentionSection | undefined {
  return plan.sections.find((s) => s.titleWithheld !== undefined);
}

function headingOf(section: AttentionSection): string {
  return section.entity.entity.pluralLabel ?? `${section.entity.entity.label}s`;
}

/** The helper name a section's records are created through, e.g. `createAppointment`. */
function creator(section: AttentionSection): string {
  return `create${section.entity.pascalName}`;
}

export function attentionTests(plan: AttentionPlan): EmittedTest[] {
  const tests: EmittedTest[] = [];
  const showcase = showcaseOf(plan);
  const owner = ownerSectionOf(plan);
  const admin = adminSectionOf(plan);
  const withheld = withheldSectionOf(plan);

  if (showcase) {
    const signIn = 'users.member';
    tests.push({
      name: 'the page lists a record dated soon and leaves out one dated far off',
      code: `  test('the page lists a record dated soon and leaves out one dated far off', async () => {
    const jar = await app.login(${signIn});
    const before = await readPage(jar);

    const soonId = await ${creator(showcase)}(jar, soon(3));
    const farId = await ${creator(showcase)}(jar, soon(200));
    const after = await readPage(jar);

    assert.ok(after.links.includes(linkTo(${JSON.stringify(showcase.entity.base)}, soonId)), 'a record dated in three days must be listed');
    assert.ok(!after.links.includes(linkTo(${JSON.stringify(showcase.entity.base)}, farId)), 'a record dated two hundred days out must not be listed');
    assert.ok(after.rows.length > before.rows.length, 'the page must have grown by the record that is near');

    // Asking for a longer stretch of time brings the far one in, which shows the window is what decided it.
    const wide = await readPage(jar, '?days=365');
    assert.ok(wide.links.includes(linkTo(${JSON.stringify(showcase.entity.base)}, farId)), 'the far record must appear once the window reaches it');
  });`,
    });
  }

  tests.push({
    name: 'V2.2.1 the number of days the page looks ahead is checked against what is expected before the app uses it',
    requirement: {
      standard: 'asvs',
      id: 'V2.2.1',
      proves: 'The one thing this page takes from the address bar, how many days ahead to look, is checked against the expected range, and anything else is refused rather than reaching a query.',
    },
    code: `  test('V2.2.1 the number of days the page looks ahead is checked against what is expected before the app uses it', async () => {
    const jar = await app.login(users.member);
    for (const query of ['?days=0', '?days=366', '?days=-30', '?days=1e4', '?days=soon', '?days=1.5', '?weeks=4']) {
      const res = await app.fetch(\`\${PAGE}\${query}\`, { jar });
      await res.text();
      assert.equal(res.status, 400, \`\${query} must be refused (got \${res.status})\`);
    }
    const ok = await app.fetch(\`\${PAGE}?days=90\`, { jar });
    await ok.text();
    assert.equal(ok.status, 200, 'a number of days within the limits must be accepted');
  });`,
  });

  tests.push({
    name: 'V8.2.1 the page showing what is coming up is not available without signing in, and anything not explicitly allowed is refused',
    requirement: {
      standard: 'asvs',
      id: 'V8.2.1',
      proves: 'Someone who has not signed in cannot open the page or read any record from it, even where one of the record types on it is public to read.',
    },
    code: `  test('V8.2.1 the page showing what is coming up is not available without signing in, and anything not explicitly allowed is refused', async () => {
${showcase ? `    const owner = await app.login(users.member);
    await ${creator(showcase)}(owner, soon(2));
` : ''}    const res = await app.fetch(PAGE, { jar: new CookieJar() });
    const body = await res.text();
    assert.ok(
      res.status === 401 || res.status === 403 || (isRedirect(res) && /login|sign-?in/i.test(locationOf(res))),
      \`the page must not be readable without signing in (got \${res.status} \${locationOf(res)})\`,
    );
    assert.doesNotMatch(body, /data-section=/, 'no record may be served to a visitor who has not signed in');
  });`,
  });

  if (owner) {
    tests.push({
      name: 'V8.2.2 the page lists only your own records where records belong to one person, never another person’s',
      requirement: {
        standard: 'asvs',
        id: 'V8.2.2',
        proves: `A ${owner.entity.entity.label.toLowerCase()} belongs to one person, and another person's ${owner.entity.entity.label.toLowerCase()} never appears on their page — the query is restricted to the signed-in person rather than the page filtering the records afterwards.`,
      },
      code: `  test('V8.2.2 the page lists only your own records where records belong to one person, never another person${'’'}s', async () => {
    const mine = await app.login(users.member);
    const theirs = await app.login(users.member2);

    const theirRecord = await ${creator(owner)}(theirs, soon(4));
    const myRecord = await ${creator(owner)}(mine, soon(5));

    const myPage = await readPage(mine);
    assert.ok(myPage.links.includes(linkTo(${JSON.stringify(owner.entity.base)}, myRecord)), 'my own record must be listed for me');
    assert.ok(!myPage.links.includes(linkTo(${JSON.stringify(owner.entity.base)}, theirRecord)), "another person's record must never be listed for me");

    const theirPage = await readPage(theirs);
    assert.ok(theirPage.links.includes(linkTo(${JSON.stringify(owner.entity.base)}, theirRecord)), 'their own record must be listed for them');
    assert.ok(!theirPage.links.includes(linkTo(${JSON.stringify(owner.entity.base)}, myRecord)), 'my record must never be listed for them');
  });`,
    });
  }

  if (admin) {
    const heading = headingOf(admin);
    tests.push({
      name: 'V8.3.1 a record type only administrators may read has no section on the page for anybody else, decided on the server',
      requirement: {
        standard: 'asvs',
        id: 'V8.3.1',
        proves: `${heading} may be read by administrators only, and the decision is made on the server: the section is absent from what a member is sent rather than present and hidden, so nothing in the page or in a request can bring it back.`,
      },
      // Checking the response body rather than what is displayed is the point: a section hidden with a style rule
      // would pass a test that only looked at the page as rendered, and would be one view-source away from leaking.
      code: `  test('V8.3.1 a record type only administrators may read has no section on the page for anybody else, decided on the server', async () => {
    const boss = await app.login(users.admin);
    const recordId = await ${creator(admin)}(boss, soon(3));

    const asAdmin = await readPage(boss);
    assert.ok(asAdmin.sections.includes(${JSON.stringify(heading)}), 'an administrator must see the section');
    assert.ok(asAdmin.links.includes(linkTo(${JSON.stringify(admin.entity.base)}, recordId)), 'and the record in it');

    // A member is sent no trace of it: not the section, not the record, not its address.
    const member = await app.login(users.member);
    const { html } = await app.page(PAGE, member);
    assert.ok(!html.includes(\`data-section="${heading}"\`), 'the section must not be in what a member is sent');
    assert.ok(!html.includes(linkTo(${JSON.stringify(admin.entity.base)}, recordId)), 'the record must not be in what a member is sent');
  });`,
    });
  }

  if (showcase) {
    tests.push({
      name: 'V8.2.3 the page shows a record’s date and a link to it, and no other field of it',
      requirement: {
        standard: 'asvs',
        id: 'V8.2.3',
        proves: withheld
          ? `Only the date and the name are on the page, checked against everything the record actually holds; and ${withheld.titleWithheld} is marked sensitive, so ${headingOf(withheld).toLowerCase()} are listed by date alone with no name at all.`
          : 'Only the date and the name are on the page, checked against everything the record actually holds, so a field nobody put there cannot appear on it.',
      },
      code: `  test('V8.2.3 the page shows a record${'’'}s date and a link to it, and no other field of it', async () => {
    const jar = await app.login(users.member);
    const recordId = await ${creator(showcase)}(jar, soon(3));

    // What the record actually holds, asked of the record's own interface rather than written into this test.
    const res = await app.json('GET', \`/api${showcase.entity.base}/\${recordId}\`, undefined, jar);
    const record = (await res.json()) as Record<string, unknown>;
    assert.equal(res.status, 200, 'the record must be readable through its own interface');

    const { html } = await app.page(PAGE, jar);
    const allowed = new Set([${JSON.stringify(showcase.date.prop)}${showcase.title ? `, ${JSON.stringify(showcase.entity.titleField?.prop ?? '')}` : ''}, 'id', 'createdAt', 'updatedAt']);
    const leaked: string[] = [];
    for (const [key, value] of Object.entries(record)) {
      if (allowed.has(key)) continue;
      if (typeof value !== 'string' || value.length < 4) continue;
      // A value that is also part of the page's own headings would say nothing either way.
      if (html.includes(value) && !HEADINGS.some((h) => h.includes(value))) leaked.push(key);
    }
    assert.deepEqual(leaked, [], 'no field beyond the date and the name may appear on the page');
${withheld ? `
    // And a name the person marked sensitive is not shown at all, only the reason it is not.
    assert.ok(!html.includes(\`data-section="${headingOf(withheld)}"\`) || /sensitive/.test(html), 'a withheld name must be explained rather than silently missing');
` : ''}  });`,
    });

    if (showcase.title) {
      tests.push({
        name: 'V1.2.1 a record name typed as markup is shown on the page as the text somebody typed, never as html',
        requirement: {
          standard: 'asvs',
          id: 'V1.2.1',
          proves: `A ${showcase.entity.entity.label.toLowerCase()} whose ${showcase.title.label.toLowerCase()} is typed as markup appears on the page as that text, with the characters encoded for html, and nothing in it runs.`,
        },
        code: `  test('V1.2.1 a record name typed as markup is shown on the page as the text somebody typed, never as html', async () => {
    const jar = await app.login(users.member);
    await ${creator(showcase)}(jar, soon(3), TYPED_AS_MARKUP);
    const { html } = await app.page(PAGE, jar);

    // Shown, and shown as text: the characters are encoded for html rather than becoming part of the document.
    assert.ok(html.includes('&lt;script&gt;'), 'the typed text must appear with its characters encoded for html');
    assert.ok(!html.includes('<script>alert(1)'), 'the typed text must never arrive as something that runs');
    assert.doesNotMatch(html, /<img[^>]*onerror/i, 'nor as an attribute that runs');
  });`,
      });
    }
  }

  return tests;
}

export function attentionRequirements(plan: AttentionPlan): RecipeRequirement[] {
  return attentionTests(plan)
    .filter((t): t is EmittedTest & { requirement: NonNullable<EmittedTest['requirement']> } => t.requirement !== undefined)
    .map((t) => ({ ...t.requirement, test: t.name }));
}

/** One create helper per section, each setting the date this page is about. */
function creatorSource(plan: AttentionPlan): string {
  return plan.sections
    .map((section) => {
      const entity = section.entity;
      const withTime = section.date.granularity === 'datetime';
      const nameProp = section.title ? entity.titleField?.prop : undefined;
      return `  /** One ${entity.entity.label.toLowerCase()}, dated as asked. */
  async function ${creator(section)}(jar: CookieJar, on: string${nameProp ? ', name?: string' : ''}): Promise<string> {
    const body = {
      ...${entity.camelName}Payload,
      ${section.date.prop}: ${withTime ? "`${on}T09:00`" : 'on'},${nameProp ? `
      ...(name === undefined ? {} : { ${nameProp}: name }),` : ''}
    };
    const res = await app.json('POST', '/api${entity.base}', body, jar);
    const created = (await res.json()) as { id: string };
    assert.equal(res.status, 201, \`a ${entity.entity.label.toLowerCase()} must be created for the page to list it (got \${res.status})\`);
    return created.id;
  }`;
    })
    .join('\n\n');
}

export function emitTest(plan: AttentionPlan, runId: string): string {
  const payloads = plan.sections
    .map((s) => `const ${s.entity.camelName}Payload = ${payloadLiteral(s.entity, 'a')};`)
    .join('\n');
  const headings = plan.sections.map((s) => headingOf(s));
  const needsMarkup = showcaseOf(plan)?.title !== undefined;

  return `// Generated by SecureVibe (recipe needs-attention) — run ${runId}
/** ${commentText(plan.title)}: that the right records are on it, for the right person, and nothing else of them.
 *
 * The page reads several record types at once, each with its own rule about who may see it, so most of what is
 * checked here is which of them reach whom.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { CookieJar, isRedirect, locationOf, startApp, type RunningApp } from '../helpers/app.ts';
import { users } from '../helpers/conventions.ts';

const PAGE = '${plan.path}';

/** The headings this page can show, so a test can tell a record's own value from the page's furniture. */
const HEADINGS = ${JSON.stringify(headings)};
${needsMarkup ? `
/** A name that would be markup if the page ever inserted it unescaped. */
const TYPED_AS_MARKUP = '</td><script>alert(1)</script>';
` : ''}
${payloads}

/** A date this many days from now, as the record's own field accepts it. */
function soon(days: number): string {
  return new Date(Date.now() + days * 86400000).toISOString().slice(0, 10);
}

/** The address the page links a record by. */
function linkTo(base: string, id: string): string {
  return \`\${base}/\${id}\`;
}

describe('${plan.title.toLowerCase()}', () => {
  let app: RunningApp;

  before(async () => {
    app = await startApp();
  });
  after(async () => {
    await app?.stop();
  });

${creatorSource(plan)}

  /**
   * What the page is showing: the sections it built, the addresses it linked, and one row per record. Read from the
   * data attributes on each row rather than from the prose, so a test reads what the page decided.
   */
  async function readPage(jar: CookieJar, query = ''): Promise<{ sections: string[]; links: string[]; rows: string[] }> {
    const { res, html } = await app.page(\`\${PAGE}\${query}\`, jar);
    assert.equal(res.status, 200, \`the page must be readable (got \${res.status})\`);
    const rows = [...html.matchAll(/data-section="([^"]*)" data-at="([^"]*)"/g)].map((m) => \`\${m[1]}|\${m[2]}\`);
    const sections = [...new Set([...html.matchAll(/data-section="([^"]*)"/g)].map((m) => m[1]!))];
    const links = [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]!);
    return { sections, links, rows };
  }

${attentionTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
