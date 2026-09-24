/**
 * Recipe 3 — **a report over existing records**.
 *
 * For every record type with something worth adding up, this writes one read-only page: how many records there are,
 * the total and average of each amount, a tally of each yes/no field, a count per option of each choice, and two
 * dates to narrow it by. It adds no columns and no way to change anything — it only reads.
 *
 * What the profile decides:
 *  - **which figures appear** comes from the described fields (amounts, yes/no answers and choices), and a field the
 *    person marked sensitive is never summarized, because a total or a breakdown can give away as much as the
 *    values themselves;
 *  - **whose records are counted** comes from the record type's `access` answer: where records belong to one person
 *    the report is over that person's own records, and an administrator — who may already read every record — sees
 *    the totals over all of them;
 *  - **whether it needs a sign-in**: always. Even for a record type anyone may read, a total taken over every
 *    record can say more than the single page of the list a visitor can see.
 *
 * The page is at `/reports/<plural>`, not `<base>/summary`, because the record type's own `<base>/:id` route is
 * registered first and would match `summary` as an id.
 */
import type { Recipe, RecipeContext, RecipeEmission, RecipeInstance } from '../types.js';
import { planEntity, summaryFieldsOf, type EntityPlan } from '../record-type/fields.js';
import { emitRoutes, emitView, reportAuth, summaryPlan, type SummaryPlan } from './emit.js';
import { emitTest, excludedSensitiveFields, summaryRequirements } from './tests.js';

export interface RecordSummaryInstance extends RecipeInstance {
  plan: SummaryPlan;
}

/** Plain language for the owner: what the page shows, and over whose records. */
function describe(plan: SummaryPlan): string {
  const entity = plan.entity;
  const plural = (entity.entity.pluralLabel ?? `${entity.entity.label}s`).toLowerCase();
  const amounts = plan.fields.filter((f) => f.kind === 'number' || f.kind === 'money').map((f) => f.label.toLowerCase());
  const choices = plan.fields.filter((f) => f.kind === 'choice').map((f) => f.label.toLowerCase());
  const yesNo = plan.fields.filter((f) => f.kind === 'boolean').map((f) => f.label.toLowerCase());
  const shows: string[] = [`how many ${plural} there are`];
  if (amounts.length > 0) shows.push(`the total and average ${amounts.join(' and ')}`);
  if (choices.length > 0) shows.push(`how many of each ${choices.join(' and ')}`);
  if (yesNo.length > 0) shows.push(`how many have ${yesNo.join(' and ')} set`);
  const list = shows.length === 1 ? shows[0]! : `${shows.slice(0, -1).join(', ')} and ${shows.at(-1)!}`;
  const sentences = [`A report page showing ${list}, for all time or between two dates you choose.`];
  if (entity.ownerScoped) {
    sentences.push(`It counts your own ${plural} only; an administrator sees the totals over everyone's.`);
  } else if (entity.adminOnly) {
    sentences.push('Only administrators can open it.');
  } else {
    sentences.push('Everyone who has signed in sees the same figures.');
  }
  const excluded = excludedSensitiveFields(plan);
  if (excluded.length > 0) {
    sentences.push(
      `${excluded.map((f) => f.label).join(' and ')} ${excluded.length === 1 ? 'is' : 'are'} left out of it, because ${excluded.length === 1 ? 'you marked it' : 'you marked them'} sensitive and a total can give away as much as the values.`,
    );
  }
  sentences.push('Nothing on the page can change your records.');
  return sentences.join(' ');
}

export const recordSummaryRecipe: Recipe<RecordSummaryInstance> = {
  id: 'record-summary',
  version: '1',
  title: 'A report over existing records',
  summary:
    'Adds a read-only page that counts a kind of record and adds up its amounts, with a date range, over only the ' +
    'records the person reading it is allowed to see.',

  plan(ctx: RecipeContext): RecordSummaryInstance[] {
    const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    return entities
      .filter((entity) => summaryFieldsOf(entity).length > 0)
      .map((entity) => {
        const plan: EntityPlan = planEntity(entity, { uploads: ctx.features.uploads });
        return { id: `${entity.name}-report`, label: `${(entity.pluralLabel ?? `${entity.label}s`).toLowerCase()} report`, plan: summaryPlan(plan) };
      });
  },

  emit(instance: RecordSummaryInstance, ctx: RecipeContext): RecipeEmission {
    const plan = instance.plan;
    return {
      description: describe(plan),
      files: [
        { path: `src/features/${plan.moduleDir}/index.ts`, contents: emitRoutes(plan, ctx.runId) },
        { path: `src/views/${plan.moduleDir}/index.ejs`, contents: emitView(plan) },
        { path: `tests/features/${plan.moduleDir}.test.ts`, contents: emitTest(plan, ctx.runId) },
      ],
      routes: [{ method: 'GET', path: plan.path, auth: reportAuth(plan).replace(/'/g, ''), entity: plan.entity.entity.name, kind: 'page', csrf: false }],
      registration: `  {
    const ${plan.entity.camelName}Report = await import('./${plan.moduleDir}/index.ts');
    ${plan.entity.camelName}Report.register(router);
    mounted.push('${instance.id}');
  }`,
      requirements: summaryRequirements(plan),
      notes: [],
    };
  },
};
