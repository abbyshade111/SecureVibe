/**
 * Recipe 2 — **a file attached to a record, handled safely**.
 *
 * When a person said one of their record types has a file on it ("each item has a photo"), this adds the page and
 * the routes for putting a file there: a column per file field, a page listing what is attached, and the two
 * actions that attach one and remove one.
 *
 * It does not implement uploading. The template already has an uploads module that streams the file with a byte
 * cap, looks inside it to confirm the type, stores it outside the web root under a random name with the person's
 * storage limit enforced, and serves it back only to whoever uploaded it. The Security Contract says files go
 * through that module and nowhere else (SC-12), so the attach route calls its `receiveUpload`. That is also what
 * makes the interesting property true for free: the only file a person can attach is the one they just sent, so a
 * record can never be pointed at somebody else's stored file.
 *
 * The recipe applies only when the uploads feature is on. Without it there is nothing safe to attach a file to, so
 * the record-type recipe leaves the field out and says so in plain language instead.
 */
import type { Recipe, RecipeContext, RecipeEmission, RecipeInstance } from '../types.js';
import { attachmentFieldsOf, planEntity, type EntityPlan } from '../record-type/fields.js';
import { attachmentPlan, emitMigration, emitRoutes, emitView, pageAuth, type AttachmentPlan } from './emit.js';
import { attachmentRequirements, emitTest } from './tests.js';

export interface RecordAttachmentInstance extends RecipeInstance {
  plan: AttachmentPlan;
}

/** Plain language for the owner: what this adds, and the one surprise worth stating up front. */
function describe(plan: AttachmentPlan): string {
  const entity = plan.entity;
  const lower = entity.entity.label.toLowerCase();
  const names = plan.fields.map((f) => f.label.toLowerCase());
  const list = names.length === 1 ? names[0]! : `${names.slice(0, -1).join(', ')} and ${names.at(-1)!}`;
  const sentences = [
    `A page on each ${lower} for keeping ${list} with it: choose a file, and it is checked and stored safely; replace it or remove it at any time.`,
    'Only pictures and PDF files are accepted, and the app looks inside each one to confirm it really is what its name says.',
  ];
  if (entity.ownerScoped) {
    sentences.push(`Each person can only reach the files on their own ${lower}.`);
  } else if (entity.adminOnly) {
    sentences.push('Only administrators can attach or see these files.');
  } else {
    sentences.push(
      `Anyone signed in who can change ${/^[aeiou]/.test(lower) ? 'an' : 'a'} ${lower} can attach a file to it, but a file stays readable only by the person who attached it and by administrators, so other people will see its name and not its contents.`,
    );
  }
  return sentences.join(' ');
}

export const recordAttachmentRecipe: Recipe<RecordAttachmentInstance> = {
  id: 'record-attachment',
  version: '1',
  title: 'A file kept with a record',
  summary:
    'Adds a page for attaching a file to a record and removing it again, using the checks the app already has for ' +
    'files: the size limit, the real file type, and where the file is stored.',

  plan(ctx: RecipeContext): RecordAttachmentInstance[] {
    const entities = (ctx.profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
    return entities
      .filter((entity) => attachmentFieldsOf(entity, { uploads: ctx.features.uploads }).length > 0)
      .map((entity) => {
        const plan: EntityPlan = planEntity(entity, { uploads: ctx.features.uploads });
        return { id: `${entity.name}-files`, label: `files kept with ${(entity.pluralLabel ?? `${entity.label}s`).toLowerCase()}`, plan: attachmentPlan(plan) };
      });
  },

  emit(instance: RecordAttachmentInstance, ctx: RecipeContext): RecipeEmission {
    const plan = instance.plan;
    const migration = ctx.nextMigrationNumber();
    return {
      description: describe(plan),
      files: [
        { path: `src/db/migrations/${migration}_${plan.entity.table}_files.sql`, contents: emitMigration(plan, ctx.runId) },
        { path: `src/features/${plan.moduleDir}/index.ts`, contents: emitRoutes(plan, ctx.runId) },
        { path: `src/views/${plan.moduleDir}/index.ejs`, contents: emitView(plan) },
        { path: `tests/features/${plan.moduleDir}.test.ts`, contents: emitTest(plan, ctx.runId) },
      ],
      routes: [
        { method: 'GET', path: plan.filesPath, auth: pageAuth(plan).replace(/'/g, ''), entity: plan.entity.entity.name, kind: 'page', csrf: false, ...(plan.entity.ownerScoped ? { owner: { entity: plan.entity.entity.name, param: 'id' } } : {}) },
        ...plan.fields.flatMap((f) => [
          // The attach route carries no synchroniser token of its own: the uploads module checks the Origin and the
          // form token itself, because a multipart body cannot be parsed before it is read.
          { method: 'POST', path: `${plan.base}/:id/files/${f.column}`, auth: plan.entity.writeAuth.replace(/'/g, ''), entity: plan.entity.entity.name, kind: 'page' as const, csrf: false, ...(plan.entity.ownerScoped ? { owner: { entity: plan.entity.entity.name, param: 'id' } } : {}) },
          { method: 'POST', path: `${plan.base}/:id/files/${f.column}/remove`, auth: plan.entity.writeAuth.replace(/'/g, ''), entity: plan.entity.entity.name, kind: 'page' as const, csrf: true, ...(plan.entity.ownerScoped ? { owner: { entity: plan.entity.entity.name, param: 'id' } } : {}) },
        ]),
      ],
      registration: `  {
    const ${plan.entity.camelName}Files = await import('./${plan.moduleDir}/index.ts');
    ${plan.entity.camelName}Files.register(router);
    mounted.push('${instance.id}');
  }`,
      requirements: attachmentRequirements(plan),
      notes: [],
    };
  },
};
