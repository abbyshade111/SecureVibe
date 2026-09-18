/**
 * The recipe runner: plans every recipe in the library against the design, then writes what they emit into the
 * scaffolded app.
 *
 * It is the only place that touches the disk, so a recipe itself stays a pure function of the design profile.
 * It also holds the recipes to the same fence as the generation agent: a file whose path is not in the template
 * manifest's `writablePaths` is refused, not written, and the run says so. Two recipes can never claim the same
 * migration number, because the numbers are handed out here.
 *
 * Safe to run twice on the same folder: files are overwritten, and the registration block and the route manifest
 * are only extended with entries that are not already there.
 */
import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { DesignArtifacts } from '@shared/design.js';
import type { TemplateManifest } from '@shared/knowledge.js';
import type { RecipeApplication } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import { matchesAnyGlob } from '../files.js';
import { RECIPES } from './registry.js';
import type { AnyRecipe, RecipeContext, RecipeRoute } from './types.js';

/** Migrations the recipes write start here, leaving 001–099 to the template itself. */
const FIRST_MIGRATION_NUMBER = 100;

const REGISTRATION_MARKER = '// --- generated features: SecureVibe appends registrations below this line (keep the order) ---';

export interface ApplyRecipesInput {
  appDir: string;
  design: DesignArtifacts;
  profile: DesignProfile;
  /** The scaffolded app's manifest; its `writablePaths` is the fence every recipe file must pass. */
  manifest: TemplateManifest;
  runId: string;
  /** Limits the run to these recipe ids (tests and future diff-aware rebuilds); every recipe by default. */
  only?: string[];
  log?: (msg: string) => void;
}

export interface ApplyRecipesResult {
  /** One entry per thing a recipe built, in the order the recipes ran. */
  applications: RecipeApplication[];
  /** Paths relative to the app folder, for the provenance manifest. */
  filesWritten: string[];
  routes: RecipeRoute[];
  /** Plain-language notes and refusals, shown to the owner and recorded on the stage. */
  warnings: string[];
}

async function writeFileAt(appDir: string, relPath: string, contents: string): Promise<void> {
  const target = join(appDir, relPath);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, contents, 'utf8');
}

/** Adds each recipe's registration block in the marked spot of `src/features/index.ts`. */
async function wireRegistrations(appDir: string, blocks: string[], warnings: string[]): Promise<string | undefined> {
  if (blocks.length === 0) return undefined;
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
  await writeFile(file, source.replace(REGISTRATION_MARKER, `${REGISTRATION_MARKER}\n${blocks.join('\n')}`), 'utf8');
  return rel;
}

async function mergeRouteManifest(appDir: string, routes: RecipeRoute[], warnings: string[]): Promise<string | undefined> {
  if (routes.length === 0) return undefined;
  const rel = 'routes.manifest.json';
  const file = join(appDir, rel);
  let existing: RecipeRoute[] = [];
  if (existsSync(file)) {
    try {
      const parsed = JSON.parse(await readFile(file, 'utf8')) as unknown;
      if (Array.isArray(parsed)) existing = parsed as RecipeRoute[];
      else if (parsed && typeof parsed === 'object' && Array.isArray((parsed as { routes?: unknown }).routes)) {
        existing = (parsed as { routes: RecipeRoute[] }).routes;
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

/**
 * Runs the library against one scaffolded app. Every recipe is asked what it would build, and each instance's
 * files are written only when all of its paths are inside the manifest's writable allow-list — a recipe that
 * strays is refused whole, so an app is never left with half a feature.
 */
export async function applyRecipes(input: ApplyRecipesInput): Promise<ApplyRecipesResult> {
  const log = input.log ?? (() => {});
  const warnings: string[] = [];
  const applications: RecipeApplication[] = [];
  const filesWritten: string[] = [];
  const allRoutes: RecipeRoute[] = [];
  const registrations: string[] = [];

  let migrationNumber = FIRST_MIGRATION_NUMBER;
  const ctx: RecipeContext = {
    design: input.design,
    profile: input.profile,
    features: input.design.buildSpec.features,
    runId: input.runId,
    nextMigrationNumber: () => migrationNumber++,
  };

  const recipes: AnyRecipe[] = input.only ? RECIPES.filter((r) => input.only!.includes(r.id)) : RECIPES;

  for (const recipe of recipes) {
    let instances;
    try {
      instances = recipe.plan(ctx);
    } catch (err) {
      warnings.push(`The "${recipe.title}" step could not work out what to build, so it was skipped: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    for (const instance of instances) {
      const emission = recipe.emit(instance, ctx);
      const outside = emission.files.map((f) => f.path).filter((p) => !matchesAnyGlob(p, input.manifest.writablePaths));
      if (outside.length > 0) {
        // A recipe may only write where the generation agent may write. This is a bug in the recipe, not
        // something the owner did, so it is reported plainly and nothing is written for this instance.
        warnings.push(`The "${recipe.title}" step was stopped because it tried to write outside the files it is allowed to change (${outside.join(', ')}). Nothing was written for ${instance.label}.`);
        continue;
      }
      for (const file of emission.files) {
        await writeFileAt(input.appDir, file.path, file.contents);
        filesWritten.push(file.path);
      }
      if (emission.registration) registrations.push(emission.registration);
      allRoutes.push(...emission.routes);
      warnings.push(...emission.notes);
      applications.push({
        recipeId: recipe.id,
        recipeVersion: recipe.version,
        instance: instance.id,
        title: recipe.title,
        description: emission.description,
        files: emission.files.map((f) => f.path),
        requirements: emission.requirements,
        notes: emission.notes,
      });
      log(`Wrote ${instance.label.toLowerCase()} (${emission.files.length} files, ${recipe.title.toLowerCase()}).`);
    }
  }

  const registered = await wireRegistrations(input.appDir, registrations, warnings);
  if (registered) filesWritten.push(registered);
  const manifestFile = await mergeRouteManifest(input.appDir, allRoutes, warnings);
  if (manifestFile) filesWritten.push(manifestFile);

  if (applications.length === 0 && warnings.length === 0) {
    warnings.push('Nothing was described that the standard building blocks could add, so the app starts from the secure baseline alone.');
  }

  return { applications, filesWritten, routes: allRoutes, warnings };
}
