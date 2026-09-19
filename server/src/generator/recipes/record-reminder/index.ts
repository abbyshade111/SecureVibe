/**
 * Recipe 4 — **a scheduled reminder before a date on a record**.
 *
 * When a record type has a date on it and the app can send email, this adds the job that tells the owner their
 * record is coming up: an hourly check, one message per record, and a column remembering that it was sent.
 *
 * It writes no scheduler of its own. The template has one (`src/lib/scheduler.ts`) that declares jobs in code only
 * and holds a lease while a job runs, so two ticks or two processes can never run the same job at once, and a mailer
 * (`src/lib/mailer.ts`) that sanitises headers and writes to a local outbox when no SMTP server is configured. This
 * recipe registers a job with the first and sends through the second.
 *
 * What the profile decides:
 *  - **whether it is built at all**: only when the scheduler and email features are both on and the record type has
 *    a date or date-and-time field. Without a way to send, a reminder is a promise nothing keeps, so nothing is
 *    written and the reason is recorded in plain language;
 *  - **which date it is about**: the first date field the person described;
 *  - **who is told**: the person the record belongs to, looked up from the record's owner — never an address stored
 *    in the record itself.
 *
 * Three decisions belong to the recipe rather than the profile, because they are safety rather than preference: a
 * run sends at most fifty messages, a record is marked before its message is sent so nobody is reminded twice, and
 * the message carries the date and a link and nothing the person wrote. Mail rests on disks and servers this app
 * does not control.
 */
import type { Recipe, RecipeContext, RecipeEmission, RecipeInstance } from '../types.js';
import { planEntity, type EntityPlan } from '../record-type/fields.js';
import { emitJob, emitMigration, reminderFieldOf, reminderPlan, type ReminderPlan } from './emit.js';
import { emitTest, reminderRequirements } from './tests.js';

export interface RecordReminderInstance extends RecipeInstance {
  plan: ReminderPlan;
}

/** Plain language for the owner: what gets sent, to whom, and what is deliberately left out of it. */
function describe(plan: ReminderPlan): string {
  const entity = plan.entity;
  const lower = entity.entity.label.toLowerCase();
  const article = /^[aeiou]/.test(lower) ? 'an' : 'a';
  return [
    `An email reminder sent up to ${plan.horizonHours} hours before ${article} ${lower}'s ${plan.field.label.toLowerCase()}, to the person the ${lower} belongs to.`,
    'It is sent once per record, and never to anybody else.',
    `The message says when it is and links to the ${lower}; it repeats nothing that was written in it, because email is not a private place.`,
    `At most ${plan.maxPerRun} reminders go out in one round, so a wrong date or a clock change cannot fill somebody's inbox.`,
    'The app checks once an hour in the background while it is running.',
  ].join(' ');
}

export const recordReminderRecipe: Recipe<RecordReminderInstance> = {
  id: 'record-reminder',
  version: '1',
  title: 'A reminder before a date on a record',
  summary:
    'Adds a background job that emails the person a record belongs to shortly before the date on it, once per ' +
    'record, with no record content in the message.',

  /** A date with nothing to send it by is worth saying out loud, or the owner is left wondering. */
  declined(ctx: RecipeContext): string[] {
    if (ctx.features.scheduler && ctx.features.email) return [];
    const out: string[] = [];
    for (const entity of (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '')) {
      const planned = planEntity(entity, { uploads: ctx.features.uploads });
      const field = reminderFieldOf(planned);
      if (!field) continue;
      const lower = planned.entity.label.toLowerCase();
      const article = /^[aeiou]/.test(lower) ? 'an' : 'a';
      const missing = !ctx.features.email ? 'this app cannot send email' : 'this app runs nothing in the background';
      out.push(`${planned.entity.label}: no reminder before ${article} ${lower}'s ${field.label.toLowerCase()} was added, because ${missing}.`);
    }
    return out;
  },

  plan(ctx: RecipeContext): RecordReminderInstance[] {
    // Without a scheduler there is nothing to run the job, and without email there is nothing to send.
    if (!ctx.features.scheduler || !ctx.features.email) return [];
    const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    const out: RecordReminderInstance[] = [];
    for (const entity of entities) {
      const planned: EntityPlan = planEntity(entity, { uploads: ctx.features.uploads });
      if (!reminderFieldOf(planned)) continue;
      const plan = reminderPlan(planned);
      if (!plan) continue;
      out.push({ id: `${entity.name}-reminder`, label: `reminders about ${(entity.pluralLabel ?? `${entity.label}s`).toLowerCase()}`, plan });
    }
    return out;
  },

  emit(instance: RecordReminderInstance, ctx: RecipeContext): RecipeEmission {
    const plan = instance.plan;
    const migration = ctx.nextMigrationNumber();
    return {
      description: describe(plan),
      files: [
        { path: `src/db/migrations/${migration}_${plan.entity.table}_reminders.sql`, contents: emitMigration(plan, ctx.runId) },
        { path: `src/features/${plan.moduleDir}/index.ts`, contents: emitJob(plan, ctx.runId) },
        { path: `tests/features/${plan.moduleDir}.test.ts`, contents: emitTest(plan, ctx.runId) },
      ],
      // A scheduled job answers no requests: there is nothing to add to the route manifest.
      routes: [],
      registration: `  {
    const ${plan.entity.camelName}Reminders = await import('./${plan.moduleDir}/index.ts');
    ${plan.entity.camelName}Reminders.register(router);
    mounted.push('${instance.id}');
  }`,
      requirements: reminderRequirements(plan),
      notes: [],
    };
  },
};
