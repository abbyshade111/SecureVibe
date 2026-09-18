/**
 * The CRUD expander: turns each entity the person described into a complete, working feature module —
 * migration, schemas, repository, routes, views and security tests — by mirroring `src/features/_example`.
 * No model call is involved, so a build in "Preview without AI" mode still produces a usable application and
 * the generation agent only has to extend what is already there.
 *
 * Everything it writes is recorded with origin `expanded` for provenance, and it never touches a protected path.
 */
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { DesignArtifacts } from '@shared/design.js';
import type { DesignProfile, EntitySpec } from '@shared/profile.js';
import { emitMigration, emitRepo, emitRoutes, emitSchema } from './expand-templates/emit.js';
import { planEntity, type EntityPlan } from './expand-templates/fields.js';
import { emitTest } from './expand-templates/tests.js';
import { emitFormView, emitListView, emitShowView } from './expand-templates/views.js';

/** Migrations the expander writes start here, leaving 001–099 to the template itself. */
const FIRST_MIGRATION_NUMBER = 100;

const REGISTRATION_MARKER = '// --- generated features: SecureVibe appends registrations below this line (keep the order) ---';

export interface ExpandInput {
  appDir: string;
  design: DesignArtifacts;
  profile: DesignProfile;
  runId: string;
  log?: (msg: string) => void;
}

export interface ExpandedEntity {
  name: string;
  label: string;
  table: string;
  routeBase: string;
  files: string[];
  droppedFields: { name: string; reason: string }[];
}

export interface ExpandResult {
  implemented: true;
  entities: ExpandedEntity[];
  /** Paths relative to the app folder, for the provenance manifest (origin `expanded`). */
  filesWritten: string[];
  routes: RouteManifestEntry[];
  warnings: string[];
}

export interface RouteManifestEntry {
  method: string;
  path: string;
  auth: string;
  entity?: string;
  kind: 'page' | 'api';
  csrf: boolean;
  owner?: { entity: string; param: string };
}

function routesFor(plan: EntityPlan): RouteManifestEntry[] {
  const read = plan.readAuth.replace(/'/g, '');
  const write = plan.writeAuth.replace(/'/g, '');
  const owner = plan.ownerScoped ? { entity: plan.entity.name, param: 'id' } : undefined;
  const page = (method: string, path: string, auth: string, withOwner: boolean): RouteManifestEntry => ({
    method,
    path,
    auth,
    entity: plan.entity.name,
    kind: 'page',
    csrf: method !== 'GET',
    ...(withOwner && owner ? { owner } : {}),
  });
  const api = (method: string, path: string, auth: string, withOwner: boolean): RouteManifestEntry => ({
    method,
    path,
    auth,
    entity: plan.entity.name,
    kind: 'api',
    csrf: method !== 'GET',
    ...(withOwner && owner ? { owner } : {}),
  });
  return [
    page('GET', plan.base, read, false),
    page('GET', `${plan.base}/new`, write, false),
    page('POST', plan.base, write, false),
    page('GET', `${plan.base}/:id`, read, true),
    page('GET', `${plan.base}/:id/edit`, write, true),
    page('POST', `${plan.base}/:id`, write, true),
    page('POST', `${plan.base}/:id/delete`, write, true),
    api('GET', `/api${plan.base}`, read, false),
    api('POST', `/api${plan.base}`, write, false),
    api('GET', `/api${plan.base}/:id`, read, true),
    api('PATCH', `/api${plan.base}/:id`, write, true),
    api('DELETE', `/api${plan.base}/:id`, write, true),
  ];
}

async function writeIfAbsent(appDir: string, relPath: string, contents: string, written: string[]): Promise<void> {
  const target = join(appDir, relPath);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, contents, 'utf8');
  written.push(relPath);
}

/** Adds `await import(...)`-free static registrations for each expanded feature, in the marked spot. */
async function wireRegistrations(appDir: string, plans: EntityPlan[], warnings: string[]): Promise<string | undefined> {
  const rel = 'src/features/index.ts';
  const file = join(appDir, rel);
  if (!existsSync(file)) {
    warnings.push('src/features/index.ts was not found, so the generated features could not be registered automatically.');
    return undefined;
  }
  const source = await readFile(file, 'utf8');
  if (!source.includes(REGISTRATION_MARKER)) {
    warnings.push('The registration marker in src/features/index.ts was missing, so the generated features could not be registered automatically.');
    return undefined;
  }
  const block = plans
    .map(
      (plan) => `  {
    const ${plan.camelName} = await import('./${plan.moduleDir}/index.ts');
    ${plan.camelName}.register(router);
    mounted.push('${plan.entity.name}');
  }`,
    )
    .join('\n');
  const replaced = source.replace(REGISTRATION_MARKER, `${REGISTRATION_MARKER}\n${block}`);
  await writeFile(file, replaced, 'utf8');
  return rel;
}

async function mergeRouteManifest(appDir: string, routes: RouteManifestEntry[], warnings: string[]): Promise<string | undefined> {
  const rel = 'routes.manifest.json';
  const file = join(appDir, rel);
  let existing: RouteManifestEntry[] = [];
  if (existsSync(file)) {
    try {
      const parsed = JSON.parse(await readFile(file, 'utf8')) as unknown;
      if (Array.isArray(parsed)) existing = parsed as RouteManifestEntry[];
      else if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { routes?: unknown }).routes)) {
        existing = (parsed as { routes: RouteManifestEntry[] }).routes;
      }
    } catch {
      warnings.push('routes.manifest.json could not be read, so it was rewritten from the generated routes.');
    }
  }
  const seen = new Set(existing.map((r) => `${r.method} ${r.path}`));
  const merged = [...existing, ...routes.filter((r) => !seen.has(`${r.method} ${r.path}`))];
  await writeFile(file, `${JSON.stringify(merged, null, 2)}\n`, 'utf8');
  return rel;
}

function entitiesOf(profile: DesignProfile): EntitySpec[] {
  return (profile.app.entities ?? []).filter((e) => e.name.trim() !== '');
}

/**
 * Writes a feature module per entity. Safe to run twice: files are overwritten, and the registration block and
 * route manifest are only extended with entries that are not already there.
 */
export async function expandEntities(input: ExpandInput): Promise<ExpandResult> {
  const { appDir, design, profile, runId } = input;
  const log = input.log ?? (() => {});
  const warnings: string[] = [];
  const uploads = design.buildSpec.features.uploads;
  const entities = entitiesOf(profile);

  if (entities.length === 0) {
    return { implemented: true, entities: [], filesWritten: [], routes: [], warnings: ['No entities were described, so nothing was expanded.'] };
  }

  const plans = entities.map((entity) => planEntity(entity, { uploads }));
  const filesWritten: string[] = [];
  const expanded: ExpandedEntity[] = [];
  const allRoutes: RouteManifestEntry[] = [];

  let migrationNumber = FIRST_MIGRATION_NUMBER;
  for (const plan of plans) {
    const files: string[] = [];
    const before = filesWritten.length;

    await writeIfAbsent(appDir, `src/db/migrations/${migrationNumber}_${plan.table}.sql`, emitMigration(plan, runId), filesWritten);
    migrationNumber += 1;
    await writeIfAbsent(appDir, `src/features/${plan.moduleDir}/schema.ts`, emitSchema(plan, runId), filesWritten);
    await writeIfAbsent(appDir, `src/features/${plan.moduleDir}/repo.ts`, emitRepo(plan, runId), filesWritten);
    await writeIfAbsent(appDir, `src/features/${plan.moduleDir}/index.ts`, emitRoutes(plan, runId), filesWritten);
    await writeIfAbsent(appDir, `src/views/${plan.moduleDir}/list.ejs`, emitListView(plan), filesWritten);
    await writeIfAbsent(appDir, `src/views/${plan.moduleDir}/show.ejs`, emitShowView(plan), filesWritten);
    await writeIfAbsent(appDir, `src/views/${plan.moduleDir}/form.ejs`, emitFormView(plan), filesWritten);
    await writeIfAbsent(appDir, `tests/features/${plan.moduleDir}.test.ts`, emitTest(plan, runId), filesWritten);

    files.push(...filesWritten.slice(before));
    const routes = routesFor(plan);
    allRoutes.push(...routes);
    for (const dropped of plan.droppedFields) {
      warnings.push(`${plan.entity.label}: the field "${dropped.name}" was left out because ${dropped.reason}.`);
    }
    expanded.push({ name: plan.entity.name, label: plan.entity.label, table: plan.table, routeBase: plan.base, files, droppedFields: plan.droppedFields });
    log(`Wrote the ${plan.entity.label.toLowerCase()} feature (${files.length} files).`);
  }

  const registered = await wireRegistrations(appDir, plans, warnings);
  if (registered) filesWritten.push(registered);
  const manifest = await mergeRouteManifest(appDir, allRoutes, warnings);
  if (manifest) filesWritten.push(manifest);

  return { implemented: true, entities: expanded, filesWritten, routes: allRoutes, warnings };
}
