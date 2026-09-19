/**
 * Recipe 6 — **one page showing what is coming up, across every kind of record**.
 *
 * Every other recipe builds something for one record type. This builds one page for the whole app: for each kind of
 * record that has a date on it, the records dated near today, soonest first, with a link to each.
 *
 * It exists because of what people ask for and do not get. An owner describes an app and then wants the thing every
 * app of that shape has — a front page that answers "what have I got on". Nothing in the wizard asks for it, so the
 * generation agent either invents one, differently each time and against whatever authorization rules it happens to
 * remember, or leaves it out and the app opens on a menu.
 *
 * The hard part is not the page, it is that the record types on it do not share one rule about who may see them.
 * Inside a single app one kind of record belongs to the person who added it, another is shared with everyone signed
 * in, a third is for administrators only. A page that gathered them together would hand every reader the union of
 * all of it, and nothing about the page would look wrong. So each section carries its own record type's rule, the
 * section for an administrators-only record type is not built at all for anybody else, and there is a test for each
 * of those that fails if it stops being true.
 *
 * What the profile decides:
 *  - **which record types appear**: those with a date or date-and-time field the person did not mark sensitive;
 *  - **whose records appear in each section**: that record type's own `access` answer;
 *  - **whether a record is named**: only where its name field is not sensitive. Where it is, records are listed by
 *    date alone with a link, and the page says why rather than leaving a gap.
 *
 * Two things this recipe refuses to do, both about not claiming to know more than the answers say:
 *  - **it never calls a record late, due or overdue.** The date is the first one the person described, which is a
 *    point in time, not a deadline — it may be a birthday or the day something was recorded. The page says when it
 *    is and lets the reader decide what that means. A system that calls a birthday overdue has stopped being
 *    trustworthy about the things it says more carefully.
 *  - **it needs a sign-in, always**, even where a record type is public to read, for the reason the report and chart
 *    pages do: a list shows one page of one kind of record, and this gathers what is near today across all of them.
 */
import type { Recipe, RecipeContext, RecipeEmission, RecipeInstance } from '../types.js';
import { dateFieldOf, planEntity, type DateField, type EntityPlan } from '../record-type/fields.js';
import { attentionPlan, emitRoutes, emitView, type AttentionPlan } from './emit.js';
import { attentionRequirements, emitTest } from './tests.js';

export interface NeedsAttentionInstance extends RecipeInstance {
  plan: AttentionPlan;
}

/** Every record type that has a date this page can gather by, with the date it will use. */
function datedEntities(ctx: RecipeContext): { entity: EntityPlan; date: DateField }[] {
  const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
  const out: { entity: EntityPlan; date: DateField }[] = [];
  for (const entity of entities) {
    const planned = planEntity(entity, { uploads: ctx.features.uploads });
    const date = dateFieldOf(planned);
    if (date) out.push({ entity: planned, date });
  }
  return out;
}

/** Plain language for the owner: what is on the page, and what is deliberately not. */
function describe(plan: AttentionPlan): string {
  const named = plan.sections.map((s) => (s.entity.entity.pluralLabel ?? `${s.entity.entity.label}s`).toLowerCase());
  const list = named.length === 1 ? named[0]! : `${named.slice(0, -1).join(', ')} and ${named.at(-1)!}`;
  const sentences = [
    `A page gathering the ${list} that are dated near today — the last ${plan.daysBack} days and however many days ahead you ask for — soonest first, each one a link to the record itself.`,
    'It is in the menu and on the front page, so it is the first thing you can open.',
    'It says when each one is and nothing more than that: it does not call anything late or overdue, because the app was never told which of your dates are deadlines and which are simply dates.',
  ];
  const ownerScoped = plan.sections.filter((s) => s.entity.ownerScoped);
  const adminOnly = plan.sections.filter((s) => s.entity.adminOnly);
  if (ownerScoped.length > 0) {
    const names = ownerScoped.map((s) => (s.entity.entity.pluralLabel ?? `${s.entity.entity.label}s`).toLowerCase());
    sentences.push(`It shows your own ${names.join(' and ')} only, never anybody else's; an administrator sees everyone's.`);
  }
  if (adminOnly.length > 0) {
    const names = adminOnly.map((s) => (s.entity.entity.pluralLabel ?? `${s.entity.entity.label}s`).toLowerCase());
    sentences.push(`The part about ${names.join(' and ')} is built only for administrators — for anyone else it is not on the page at all, rather than on it and hidden.`);
  }
  const withheld = plan.sections.filter((s) => s.titleWithheld !== undefined);
  if (withheld.length > 0) {
    sentences.push(
      `${withheld.map((s) => s.titleWithheld!).join(' and ')} ${withheld.length === 1 ? 'is' : 'are'} not shown on it, because ${withheld.length === 1 ? 'you marked it' : 'you marked them'} sensitive; those records are listed by date with a link instead.`,
    );
  }
  sentences.push(`At most ${plan.perSection} of each kind are listed, with a link to the full list when there are more.`);
  sentences.push('Nothing on the page can change your records.');
  return sentences.join(' ');
}

export const needsAttentionRecipe: Recipe<NeedsAttentionInstance> = {
  id: 'needs-attention',
  version: '1',
  title: 'One page showing what is coming up',
  summary:
    'Adds a single page, in the menu, gathering the records dated near today from every kind of record that has a ' +
    'date, with each kind kept to its own rule about who may see it.',

  /**
   * A record type whose only date the person marked sensitive is worth a sentence: the page could have gathered it,
   * and it is better for the owner to know the date was left off deliberately than to wonder where it went.
   */
  declined(ctx: RecipeContext): string[] {
    const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    const out: string[] = [];
    for (const entity of entities) {
      const planned = planEntity(entity, { uploads: ctx.features.uploads });
      if (dateFieldOf(planned)) continue;
      for (const field of planned.fields.filter((f) => f.field.sensitive && (f.control === 'date' || f.control === 'datetime-local'))) {
        out.push(
          `${planned.entity.label}: ${field.field.label.toLowerCase()} is not gathered onto the page showing what is coming up, because you marked it sensitive and that page is read across the whole app.`,
        );
      }
    }
    return out;
  },

  plan(ctx: RecipeContext): NeedsAttentionInstance[] {
    const dated = datedEntities(ctx);
    // With no dates anywhere there is nothing for the page to gather, and an empty page is worse than no page.
    if (dated.length === 0) return [];
    return [{ id: 'coming-up', label: 'what is coming up', plan: attentionPlan(dated) }];
  },

  emit(instance: NeedsAttentionInstance, ctx: RecipeContext): RecipeEmission {
    const plan = instance.plan;
    return {
      description: describe(plan),
      files: [
        { path: `src/features/${plan.moduleDir}/index.ts`, contents: emitRoutes(plan, ctx.runId) },
        { path: `src/views/${plan.moduleDir}/index.ejs`, contents: emitView(plan) },
        { path: `tests/features/${plan.moduleDir}.test.ts`, contents: emitTest(plan, ctx.runId) },
      ],
      // No `entity`: the page belongs to no single record type, which is exactly why its route asks for the menu.
      routes: [{ method: 'GET', path: plan.path, auth: 'user', kind: 'page', csrf: false }],
      registration: `  {
    const comingUp = await import('./${plan.moduleDir}/index.ts');
    comingUp.register(router);
    mounted.push('${instance.id}');
  }`,
      requirements: attentionRequirements(plan),
      notes: [],
    };
  },
};
