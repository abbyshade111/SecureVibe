/**
 * Recipe 1 — **a record type with list, add, edit and delete**.
 *
 * For every kind of record the person described in the wizard, this writes a complete, working feature module by
 * mirroring `src/features/_example`: a migration, strict validation rules, a repository, the pages and the JSON
 * interface, the views, and the security tests. No model call is involved, so a build in "Preview without AI"
 * mode still produces a usable application, and the generation agent only has to extend what is already there.
 *
 * What the recipe decides, and why it is the profile that decides it:
 *  - **who may read and write** comes from the record type's `access` answer (owner-only, shared, public to
 *    read, administrators only) and becomes the route registry's `auth` value plus an ownership check;
 *  - **which fields exist** comes from the described fields; a field whose type the recipe cannot build safely
 *    is left out with a reason the owner can read, never guessed at;
 *  - **which fields are encrypted at rest** comes from the "sensitive" answer on each field;
 *  - **the per-person quota and the page-size cap** are fixed limits the emitted tests then check.
 */
import type { EntitySpec } from '@shared/profile.js';
import type { Recipe, RecipeContext, RecipeEmission, RecipeInstance, RecipeRoute } from '../types.js';
import { emitMigration, emitRepo, emitRoutes, emitSchema } from './emit.js';
import { planEntity, type EntityPlan } from './fields.js';
import { emitTest, recordTypeRequirements } from './tests.js';
import { emitFormView, emitListView, emitShowView } from './views.js';

export interface RecordTypeInstance extends RecipeInstance {
  entity: EntitySpec;
  plan: EntityPlan;
}

function routesFor(plan: EntityPlan): RecipeRoute[] {
  const read = plan.readAuth.replace(/'/g, '');
  const write = plan.writeAuth.replace(/'/g, '');
  const owner = plan.ownerScoped ? { entity: plan.entity.name, param: 'id' } : undefined;
  const route = (kind: 'page' | 'api', method: string, path: string, auth: string, withOwner: boolean): RecipeRoute => ({
    method,
    path,
    auth,
    entity: plan.entity.name,
    kind,
    csrf: method !== 'GET',
    ...(withOwner && owner ? { owner } : {}),
  });
  return [
    route('page', 'GET', plan.base, read, false),
    route('page', 'GET', `${plan.base}/new`, write, false),
    route('page', 'POST', plan.base, write, false),
    route('page', 'GET', `${plan.base}/:id`, read, true),
    route('page', 'GET', `${plan.base}/:id/edit`, write, true),
    route('page', 'POST', `${plan.base}/:id`, write, true),
    route('page', 'POST', `${plan.base}/:id/delete`, write, true),
    route('api', 'GET', `/api${plan.base}`, read, false),
    route('api', 'POST', `/api${plan.base}`, write, false),
    route('api', 'GET', `/api${plan.base}/:id`, read, true),
    route('api', 'PATCH', `/api${plan.base}/:id`, write, true),
    route('api', 'DELETE', `/api${plan.base}/:id`, write, true),
  ];
}

/** Plain language for the owner: what this record type adds, and who can see it. */
function describe(plan: EntityPlan): string {
  const plural = (plan.entity.pluralLabel ?? `${plan.entity.label}s`).toLowerCase();
  const who = plan.adminOnly
    ? 'Only administrators can see or change them.'
    : plan.ownerScoped
      ? 'Each person sees only their own; administrators can see all of them.'
      : plan.publicRead
        ? 'Anyone can read the list; only signed-in people can add or change anything.'
        : 'Everyone who has signed in can see them; each record remembers who added it.';
  const encrypted = plan.fields.filter((f) => f.encrypted);
  const sentences = [`Pages and a data interface for ${plural}: a list, a page per record, and forms to add, change and delete one.`, who];
  if (plan.summaries.length > 0) {
    sentences.push('The list also has a report page that counts them and adds up the amounts.');
  }
  sentences.push('The list links to a chart of how many were added each month.');
  if (plan.attachments.length > 0) {
    const names = plan.attachments.map((f) => f.label.toLowerCase());
    sentences.push(`Each one also has a page for keeping ${names.length === 1 ? names[0]! : `${names.slice(0, -1).join(', ')} and ${names.at(-1)!}`} with it.`);
  }
  if (encrypted.length > 0) {
    sentences.push(`${encrypted.map((f) => f.field.label).join(' and ')} ${encrypted.length === 1 ? 'is' : 'are'} scrambled in the database, so reading the file gives nothing away.`);
  }
  sentences.push(`One person can keep up to ${plan.quota} ${plural}, and a list never returns more than one page at a time.`);
  return sentences.join(' ');
}

export const recordTypeRecipe: Recipe<RecordTypeInstance> = {
  id: 'record-type',
  version: '4',
  title: 'A record type with list, add, edit and delete',
  summary:
    'Adds pages and a data interface for one kind of record the person described, with sign-in, ownership checks, ' +
    'input rules, a per-person limit and its own tests.',

  plan(ctx: RecipeContext): RecordTypeInstance[] {
    const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    return entities.map((entity) => {
      const plan = planEntity(entity, { uploads: ctx.features.uploads });
      return { id: entity.name, label: entity.label || entity.name, entity, plan };
    });
  },

  emit(instance: RecordTypeInstance, ctx: RecipeContext): RecipeEmission {
    const { plan } = instance;
    const migration = ctx.nextMigrationNumber();
    return {
      description: describe(plan),
      files: [
        { path: `src/db/migrations/${migration}_${plan.table}.sql`, contents: emitMigration(plan, ctx.runId) },
        { path: `src/features/${plan.moduleDir}/schema.ts`, contents: emitSchema(plan, ctx.runId) },
        { path: `src/features/${plan.moduleDir}/repo.ts`, contents: emitRepo(plan, ctx.runId) },
        { path: `src/features/${plan.moduleDir}/index.ts`, contents: emitRoutes(plan, ctx.runId) },
        { path: `src/views/${plan.moduleDir}/list.ejs`, contents: emitListView(plan) },
        { path: `src/views/${plan.moduleDir}/show.ejs`, contents: emitShowView(plan) },
        { path: `src/views/${plan.moduleDir}/form.ejs`, contents: emitFormView(plan) },
        { path: `tests/features/${plan.moduleDir}.test.ts`, contents: emitTest(plan, ctx.runId) },
      ],
      routes: routesFor(plan),
      registration: `  {
    const ${plan.camelName} = await import('./${plan.moduleDir}/index.ts');
    ${plan.camelName}.register(router);
    mounted.push('${plan.entity.name}');
  }`,
      requirements: recordTypeRequirements(plan),
      notes: plan.droppedFields.map((d) => `${plan.entity.label}: the field "${d.name}" was left out because ${d.reason}.`),
    };
  },
};
