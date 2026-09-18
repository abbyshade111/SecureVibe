/**
 * The recipe library's contract.
 *
 * A **recipe** is a named, tested way to add one kind of thing to a generated application — a record type with
 * its pages, a file upload, a summary page, a scheduled job. SecureVibe applies recipes deterministically from
 * the design profile: the same answers always produce the same code, no model call is involved, and the
 * generation agent extends what the recipes wrote instead of re-deriving the same patterns on every build.
 *
 * Four things make a recipe worth having rather than being a code generator with a nice name:
 *
 * 1. **Plain language.** `title` and the `description` each application returns are written for the owner, who
 *    is not a programmer. They are what the reports and the build page say the app gained.
 * 2. **Driven by the profile, not by free-writing.** `plan()` reads the design and decides how many instances
 *    there are; `emit()` is a pure function from one instance to files. Nothing here reads or writes the disk,
 *    so a recipe can be tested by calling it.
 * 3. **Its own tests, and an honest mapping.** `emit()` returns the tests as ordinary emitted files, plus the
 *    requirements those tests speak to. The evidence is the test result the normal test runner collects; the
 *    mapping only says which test covers which requirement. A recipe claiming a requirement it does not test is
 *    a contract violation, and `recipes.contract.test.ts` fails on it.
 * 4. **A stable identity.** `id` never changes and is never reused; `version` is bumped when the emitted code
 *    changes. Both, with the instance, are recorded per file in `securevibe.provenance.json`, so a later build,
 *    a template upgrade and the version diff can all tell which recipe produced which file.
 *
 * Recipes are held to the same fence as the generation agent: every path a recipe emits must match the
 * template manifest's `writablePaths`, which `apply.ts` checks before writing anything.
 */
import type { BuildSpec, DesignArtifacts } from '@shared/design.js';
import type { RecipeApplication } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';

/** One file a recipe emits, with its path relative to the app folder. */
export interface RecipeFile {
  path: string;
  contents: string;
}

/** A route the recipe registers, for `routes.manifest.json` (and so the runtime scan can probe it). */
export interface RecipeRoute {
  method: string;
  path: string;
  auth: string;
  entity?: string;
  kind: 'page' | 'api';
  csrf: boolean;
  owner?: { entity: string; param: string };
}

/**
 * A requirement one of the recipe's own tests speaks to. `test` must be the exact name of a test the recipe
 * emits, and must start with `id`, because that is how `compliance/evidence.ts` credits a test result to a
 * requirement. Nothing here asserts that the requirement is met: the test passing does that, or it does not.
 */
export interface RecipeRequirement {
  standard: 'asvs' | 'aisvs';
  id: string;
  test: string;
  /** Plain language: what that test actually shows. */
  proves: string;
}

/** What a recipe produces for one instance. Pure: no file system, no network, no model call. */
export interface RecipeEmission {
  /** Plain-language description of what this instance adds, written for the owner. */
  description: string;
  files: RecipeFile[];
  routes: RecipeRoute[];
  /**
   * Lines to insert into `src/features/index.ts` at the generated-features marker, already indented. Omit when
   * the recipe registers nothing.
   */
  registration?: string;
  requirements: RecipeRequirement[];
  /** Anything left out and why, in plain language (the build page and the reports show these). */
  notes: string[];
}

/** Everything a recipe may read. Deliberately small: the profile and the design decide, nothing else. */
export interface RecipeContext {
  design: DesignArtifacts;
  profile: DesignProfile;
  /** The feature toggles the design engine settled (uploads, scheduler, ai, …). */
  features: BuildSpec['features'];
  /** Goes into the provenance header of every emitted file. */
  runId: string;
  /**
   * The next free migration number (100 upwards; 1–99 belong to the template). A recipe calls this once per
   * migration it emits, so two recipes can never claim the same number.
   */
  nextMigrationNumber: () => number;
}

/** The smallest thing a recipe builds, identified stably within a project. */
export interface RecipeInstance {
  /** Stable within the project — the record type's name, the job's name. Used in the provenance. */
  id: string;
  /** What the owner calls it. */
  label: string;
}

export interface Recipe<I extends RecipeInstance = RecipeInstance> {
  /** Stable identity. Never changed, never reused. */
  id: string;
  /** Bumped when the emitted code changes in a way a rebuild should pick up. */
  version: string;
  /** Plain-language name of what the recipe adds, for the owner. */
  title: string;
  /** One or two plain-language sentences about the recipe itself (no instance detail). */
  summary: string;
  /** One instance per thing this recipe should build for this design; an empty array when it does not apply. */
  plan(ctx: RecipeContext): I[];
  /** The files, routes, tests and requirement mapping for one instance. */
  emit(instance: I, ctx: RecipeContext): RecipeEmission;
}

/** A recipe with its instance type erased, for the registry and the runner. */
export type AnyRecipe = Recipe<RecipeInstance>;

export type { RecipeApplication };
