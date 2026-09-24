/**
 * Test emitter for the record-reminder recipe.
 *
 * The job is driven through the test-mode endpoint `POST /__securevibe/run-jobs`, which runs it now whatever its
 * hourly interval says (CONTRACTS §1.16). Without that the tests would have to wait for a scheduler tick, and a
 * reminder that is only due once an hour would never be observed at all.
 *
 * What the messages say is read from the local outbox the mailer writes to when no SMTP server is configured, which
 * is the same path the template's own email test uses.
 */
import { commentText, jsString } from '../js-literal.js';
import type { RecipeRequirement } from '../types.js';
import { payloadLiteral } from '../record-type/tests.js';
import type { ReminderPlan } from './emit.js';

export interface EmittedTest {
  name: string;
  code: string;
  requirement?: Omit<RecipeRequirement, 'test'>;
}

export function reminderTests(plan: ReminderPlan): EmittedTest[] {
  const entity = plan.entity;
  const name = entity.entity.name;
  const lower = entity.entity.label.toLowerCase();
  const tests: EmittedTest[] = [];

  tests.push({
    name: `${name}: a reminder goes out once for a ${lower} that is coming up, and not for one that is far off`,
    code: `  test(${jsString(`${name}: a reminder goes out once for a ${lower} that is coming up, and not for one that is far off`)}, async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(users.member);
    const soon = await createRecord(jar, dueIn(2));
    const later = await createRecord(jar, dueIn(24 * 7));

    const ran = await runJob();
    assert.ok(ran.includes(JOB), \`the reminder job must have run (ran: \${ran.join(', ') || 'nothing'})\`);

    const mail = outbox();
    const forSoon = mail.filter((m) => m.includes(soon));
    assert.equal(forSoon.length, 1, \`exactly one reminder must go out for the ${lower} that is coming up (got \${forSoon.length})\`);
    assert.equal(mail.filter((m) => m.includes(later)).length, 0, ${jsString(`nothing may be sent about a ${lower} a week away`)});
    assert.match(forSoon[0]!, /Sign in to see it/, 'the reminder must point the person at the app');

    // Marked as reminded, so the next run has nothing to do.
    assert.equal(remindedAt(soon) === null, false, ${jsString(`the ${lower} must be marked as reminded`)});
    assert.equal(remindedAt(later), null, ${jsString(`the ${lower} a week away must not be marked`)});
  });`,
  });

  tests.push({
    name: `V8.2.2 ${name}: a reminder about a record only ever reaches the person whose own record it is`,
    requirement: {
      standard: 'asvs',
      id: 'V8.2.2',
      proves:
        'The address a reminder is sent to is looked up from the record’s owner, never taken from the record, so one person’s ' +
        'record is never mentioned in another person’s mail.',
    },
    code: `  test('V8.2.2 ${name}: a reminder about a record only ever reaches the person whose own record it is', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const mine = await createRecord(await app.login(users.member), dueIn(3));
    const theirs = await createRecord(await app.login(users.member2), dueIn(3));

    await runJob();
    const mail = outbox();

    const aboutMine = mail.filter((m) => m.includes(mine));
    const aboutTheirs = mail.filter((m) => m.includes(theirs));
    assert.equal(aboutMine.length, 1, 'one reminder about my own record');
    assert.equal(aboutTheirs.length, 1, 'one reminder about theirs');
    assert.match(aboutMine[0]!, new RegExp(\`To:.*\${users.member}\`, 'i'), 'my reminder must be addressed to me');
    assert.match(aboutTheirs[0]!, new RegExp(\`To:.*\${users.member2}\`, 'i'), 'their reminder must be addressed to them');
    assert.doesNotMatch(aboutMine[0]!, new RegExp(users.member2, 'i'), 'my reminder must not mention anybody else');
    assert.doesNotMatch(aboutTheirs[0]!, new RegExp(users.member, 'i'), 'their reminder must not mention me');
  });`,
  });

  tests.push({
    name: `V2.4.1 ${name}: a run cannot flood a mailbox: at most a capped number of reminders go out, and never the same one twice`,
    requirement: {
      standard: 'asvs',
      id: 'V2.4.1',
      proves: `One run sends no more than ${plan.maxPerRun} reminders however many ${(entity.entity.pluralLabel ?? `${entity.entity.label}s`).toLowerCase()} are due, and running it again sends nothing further, so neither a second run nor a clock jump can fill a mailbox.`,
    },
    code: `  test('V2.4.1 ${name}: a run cannot flood a mailbox: at most a capped number of reminders go out, and never the same one twice', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(users.member);
    // A few more than the cap, so the cap is the thing being measured.
    const wanted = MAX_PER_RUN + 3;
    for (let i = 0; i < wanted; i++) await createRecord(jar, dueIn(1 + (i % 20)));

    const first = outbox().length;
    await runJob();
    const afterOne = outbox().length - first;
    assert.ok(afterOne <= MAX_PER_RUN, \`one run must send at most \${MAX_PER_RUN} reminders (sent \${afterOne})\`);
    assert.ok(afterOne > 0, 'a run with records due must send something');

    // Running again may pick up the ones left over, but must never repeat one already sent.
    await runJob();
    const total = outbox();
    const ids = total.flatMap((m) => [...m.matchAll(/${entity.base.slice(1)}\\/([0-9a-f-]{36})/g)].map((x) => x[1]!));
    const seen = new Set<string>();
    const repeated = ids.filter((id) => (seen.has(id) ? true : (seen.add(id), false)));
    assert.deepEqual(repeated, [], ${jsString(`no ${lower} may be reminded about twice`)});
  });`,
  });

  tests.push({
    name: `${name}: the reminder carries the date and a link, and nothing the person wrote`,
    // No requirement is claimed for this: keeping record content out of email is a design decision this recipe
    // makes, and no ASVS requirement covers what a notification may carry. The test still earns its place.
    code: `  test('${name}: the reminder carries the date and a link, and nothing the person wrote', async (t) => {
    if (!enabled) return t.skip(SKIP);
    const jar = await app.login(users.member);
    const id = await createRecord(jar, dueIn(2), SECRETS);
    await runJob();

    const mail = outbox().filter((m) => m.includes(id));
    assert.equal(mail.length, 1, 'one reminder');
    for (const [field, value] of Object.entries(SECRETS)) {
      if (typeof value !== 'string' || value.length < 6) continue;
      assert.ok(!mail[0]!.includes(value), \`the reminder must not repeat the \${field} the person wrote\`);
    }
  });`,
  });

  return tests;
}

export function reminderRequirements(plan: ReminderPlan): RecipeRequirement[] {
  return reminderTests(plan)
    .filter((t): t is EmittedTest & { requirement: NonNullable<EmittedTest['requirement']> } => t.requirement !== undefined)
    .map((t) => ({ ...t.requirement, test: t.name }));
}

export function emitTest(plan: ReminderPlan, runId: string): string {
  const entity = plan.entity;
  const dateProp = plan.field.prop;
  // A value in the shape the form produces, so the record is created exactly as a person would create it.
  const dueExpression =
    plan.field.granularity === 'date'
      ? `new Date(Date.now() - OFFSET_MS + hours * 3600_000).toISOString().slice(0, 10)`
      : `new Date(Date.now() - OFFSET_MS + hours * 3600_000).toISOString().slice(0, 16)`;
  // Distinctive text for the "nothing the person wrote" test, in every free-text field the form has.
  const secretFields = entity.fields.filter((f) => f.control === 'text' || f.control === 'textarea');

  return `// Generated by SecureVibe (recipe record-reminder) — run ${runId}
/** Reminders about ${commentText((entity.entity.pluralLabel ?? `${entity.entity.label}s`).toLowerCase())}: who is told, how often, and what the message carries. */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { CookieJar, startApp, type RunningApp } from '../helpers/app.ts';
import { users } from '../helpers/conventions.ts';

const API = '/api${entity.base}';
const JOB = '${plan.jobName}';
const MAX_PER_RUN = ${plan.maxPerRun};
const SKIP = 'this app has no scheduler or no email, so nothing sends reminders';

/** The date is stored as it was typed, in this computer's own time zone, so the test builds it the same way. */
const OFFSET_MS = new Date().getTimezoneOffset() * 60_000;

/** A body for creating one record, the same shape the record's own tests use. */
const PAYLOAD = ${payloadLiteral(entity, 'a')};

/** Distinctive text in every free-text field, to prove none of it travels in a message. */
const SECRETS = {
${secretFields.map((f) => `  ${f.prop}: 'zqxjk-${f.prop}-private-note',`).join('\n')}
};

describe('${entity.entity.name} reminders', () => {
  let app: RunningApp;
  let enabled = false;

  before(async () => {
    app = await startApp();
    enabled = (await app.featureEnabled('scheduler')) && (await app.featureEnabled('email'));
  });
  after(async () => {
    await app?.stop();
  });

  /** A value for the ${commentText(plan.field.label.toLowerCase())} field, \`hours\` from now. */
  function dueIn(hours: number): string {
    return ${dueExpression};
  }

  async function createRecord(jar: CookieJar, due: string, extra: Record<string, unknown> = {}): Promise<string> {
    const res = await app.json('POST', API, { ...PAYLOAD, ...extra, ${dateProp}: due }, jar);
    const body = (await res.json()) as { id: string };
    assert.equal(res.status, 201, \`the ${entity.entity.label.toLowerCase()} must be created (got \${res.status})\`);
    return body.id;
  }

  /** Runs the scheduled jobs now, whatever their interval says (test mode only, administrators only). */
  async function runJob(): Promise<string[]> {
    const admin = await app.login(users.admin);
    const res = await app.json('POST', '/__securevibe/run-jobs', { job: JOB }, admin);
    const body = (await res.json()) as { ran?: string[] };
    assert.equal(res.status, 200, \`the test-mode job runner must answer (got \${res.status})\`);
    return body.ran ?? [];
  }

  /** Every message the app has written to its local outbox. */
  function outbox(): string[] {
    const dir = join(app.dataDir, 'outbox');
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter((f) => f.endsWith('.eml'))
      .map((f) => readFileSync(join(dir, f), 'utf8'));
  }

  function remindedAt(id: string): string | null {
    return app.dbAll<{ reminded_at: string | null }>('SELECT reminded_at FROM ${entity.table} WHERE id = ?', id)[0]?.reminded_at ?? null;
  }

${reminderTests(plan)
  .map((t) => t.code)
  .join('\n\n')}
});
`;
}
