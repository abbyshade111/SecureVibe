/**
 * Recipe 5 — **a chart of how records change over time**.
 *
 * For every kind of record, this writes one read-only page that draws how many were added each month, and the
 * monthly total of each amount the records carry. It adds no columns and no way to change anything: it only reads.
 *
 * Why a chart is worth a recipe of its own rather than being left to the generation agent: almost every app wants
 * one, and a chart is the place where a generated app is most likely to go wrong in a way nobody notices. The usual
 * way to draw one is a library fetched from somewhere else and a script that assembles markup in the browser, which
 * is a script running on a page that already shows somebody's records, from a file the app does not control. So the
 * recipe draws the picture on the server, out of whole numbers, using the page template's own escaping — no
 * library, no script, no stylesheet, nothing fetched. See `emit.ts` for the four decisions that make that hold.
 *
 * What the profile decides:
 *  - **what is drawn**: always how many records were added each month, plus one picture per amount field. Choices
 *    and yes/no fields are left to the report page, which already tallies them;
 *  - **whose records are drawn** comes from the record type's `access` answer, the same rule as the report;
 *  - **whether it needs a sign-in**: always, even for a record type anyone may read. A list shows one page of
 *    records; a chart is a shape taken over all of them, and says more than the list does.
 *  - a field the person marked sensitive is never drawn, because a month by month total can give away as much as
 *    the values, and a chart makes a small number of records easy to read straight off the page.
 *
 * The page is at `/charts/<plural>` rather than `<base>/chart`, because the record type's own `<base>/:id` route is
 * registered first and would match `chart` as a record id.
 */
import type { Recipe, RecipeContext, RecipeEmission, RecipeInstance } from '../types.js';
import { planEntity, type EntityPlan } from '../record-type/fields.js';
import { chartAuth, chartPlan, emitRoutes, emitView, type ChartPlan } from './emit.js';
import { chartRequirements, emitTest, excludedSensitiveAmounts } from './tests.js';

export interface RecordChartInstance extends RecipeInstance {
  plan: ChartPlan;
}

/** Plain language for the owner: what the page draws, and over whose records. */
function describe(plan: ChartPlan): string {
  const entity = plan.entity;
  const plural = (entity.entity.pluralLabel ?? `${entity.entity.label}s`).toLowerCase();
  const amounts = plan.series.filter((s) => s.kind !== 'count').map((s) => s.label.replace(/^Total /, '').toLowerCase());
  const shows = [`how many ${plural} were added each month`];
  if (amounts.length > 0) shows.push(`the monthly total of ${amounts.length === 1 ? amounts[0]! : `${amounts.slice(0, -1).join(', ')} and ${amounts.at(-1)!}`}`);
  const sentences = [
    `A page that draws ${shows.join(' and ')}, as bars month by month, for as many months back as you ask for.`,
    'The picture is drawn by the app itself rather than by anything fetched from elsewhere, and the same numbers are listed in a table underneath it, so they can be read without seeing the picture.',
  ];
  if (entity.ownerScoped) {
    sentences.push(`It is drawn from your own ${plural} only; an administrator sees the shape over everyone's.`);
  } else if (entity.adminOnly) {
    sentences.push('Only administrators can open it.');
  } else {
    sentences.push('Everyone who has signed in sees the same picture.');
  }
  const excluded = excludedSensitiveAmounts(plan);
  if (excluded.length > 0) {
    sentences.push(
      `${excluded.map((f) => f.label).join(' and ')} ${excluded.length === 1 ? 'is' : 'are'} not drawn, because ${excluded.length === 1 ? 'you marked it' : 'you marked them'} sensitive and a monthly total can give away as much as the values.`,
    );
  }
  sentences.push('Nothing on the page can change your records.');
  return sentences.join(' ');
}

export const recordChartRecipe: Recipe<RecordChartInstance> = {
  id: 'record-chart',
  version: '1',
  title: 'A chart of how records change over time',
  summary:
    'Adds a read-only page that draws how many records were added each month, and the monthly total of each ' +
    'amount, as bars the app draws itself with no chart library, no script and nothing fetched from elsewhere.',

  plan(ctx: RecipeContext): RecordChartInstance[] {
    // Every record type can be charted: each one records when it was added, which is what the chart counts by. The
    // filter is the record-type recipe's own, so the link it puts on the list page can never point at a page that
    // was not written.
    const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    return entities.map((entity) => {
      const plan: EntityPlan = planEntity(entity, { uploads: ctx.features.uploads });
      return { id: `${entity.name}-chart`, label: `${(entity.pluralLabel ?? `${entity.label}s`).toLowerCase()} chart`, plan: chartPlan(plan) };
    });
  },

  emit(instance: RecordChartInstance, ctx: RecipeContext): RecipeEmission {
    const plan = instance.plan;
    return {
      description: describe(plan),
      files: [
        { path: `src/features/${plan.moduleDir}/index.ts`, contents: emitRoutes(plan, ctx.runId) },
        { path: `src/views/${plan.moduleDir}/index.ejs`, contents: emitView(plan) },
        { path: `tests/features/${plan.moduleDir}.test.ts`, contents: emitTest(plan, ctx.runId) },
      ],
      routes: [{ method: 'GET', path: plan.path, auth: chartAuth(plan).replace(/'/g, ''), entity: plan.entity.entity.name, kind: 'page', csrf: false }],
      registration: `  {
    const ${plan.entity.camelName}Chart = await import('./${plan.moduleDir}/index.ts');
    ${plan.entity.camelName}Chart.register(router);
    mounted.push('${instance.id}');
  }`,
      requirements: chartRequirements(plan),
      notes: [],
    };
  },
};
