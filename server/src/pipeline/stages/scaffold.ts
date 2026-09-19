/**
 * `scaffold`: archives any previous `app/` to `app-v<N>/`, then copies and configures the hardened template
 * (generator/scaffold.ts) into the new `app/`.
 */
import type { StageResult } from '@shared/pipeline.js';
import { applyRecipes, markGeneratedFiles, recordRecipes, refreshDerivedFiles, scaffoldApp } from '../../generator/index.js';
import { finishStage, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';

export async function runScaffold(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'scaffold');
  if (!ctx.design || !ctx.profile) {
    return finishStage(ctx, 'scaffold', 'failed', 'The design was not ready, so nothing could be scaffolded.', started);
  }

  const archived = ctx.store.archiveApp(ctx.project.id);
  if (archived.archivedTo) ctx.log('scaffold', `Kept the previous build at ${archived.archivedTo}.`);

  try {
    const result = await scaffoldApp({
      templateDir: ctx.config.paths.templateDir,
      projectDir: ctx.paths.dir,
      appDir: ctx.appDir,
      design: ctx.design,
      profile: ctx.profile,
      buildSpec: ctx.design.buildSpec,
      settings: ctx.settings,
      runId: ctx.run.id,
      projectId: ctx.project.id,
      securevibeVersion: ctx.config.version,
      knowledgeDir: ctx.config.paths.knowledgeDir,
      ...(ctx.project.lastRunId ? { previousRunId: ctx.project.lastRunId } : {}),
      log: (msg) => ctx.log('scaffold', msg),
    });
    ctx.manifest = result.manifest;
    ctx.featureFlags = result.featureFlags;
    ctx.provenance = result.provenance;

    // Apply the recipe library (generator/recipes): named, tested building blocks — a record type with its
    // pages, and in time uploads, summary pages and scheduled jobs — written deterministically from the design.
    // Even a build without AI therefore produces a usable application, and the generation agent extends what the
    // recipes wrote instead of re-deriving the same patterns.
    const recipes = await applyRecipes({
      appDir: ctx.appDir,
      design: ctx.design,
      profile: ctx.profile,
      manifest: result.manifest,
      runId: ctx.run.id,
      log: (msg) => ctx.log('scaffold', msg),
    });
    if (recipes.filesWritten.length > 0) {
      ctx.provenance = markGeneratedFiles(ctx.provenance, ctx.appDir, recipes.filesWritten, 'expanded');
      ctx.provenance = recordRecipes(ctx.provenance, ctx.appDir, recipes.applications);
    }
    for (const warning of recipes.warnings) ctx.log('scaffold', warning);
    if (ctx.provenance) ctx.provenance = markGeneratedFiles(ctx.provenance, ctx.appDir, ['routes.manifest.json'], 'expanded');
    const refreshed = await refreshDerivedFiles({ appDir: ctx.appDir, projectDir: ctx.paths.dir, runId: ctx.run.id, manifest: ctx.manifest, provenance: ctx.provenance });
    if (refreshed.provenance) ctx.provenance = refreshed.provenance;
    const routeWarnings = refreshed.warnings;
    for (const warning of routeWarnings) ctx.log('scaffold', warning);

    const recordTypes = recipes.applications.filter((a) => a.recipeId === 'record-type');
    const built = recordTypes.length > 0 ? ` It already has pages and an interface for ${recordTypes.map((a) => a.instance.toLowerCase()).join(', ')}.` : '';
    const summary = result.nodeModulesFastPath
      ? `The application folder is ready, with the packages already installed and the first administrator account created.${built}`
      : `The application folder is ready. Packages will be installed next.${built}`;
    return finishStage(ctx, 'scaffold', 'passed', summary, started, {
      details: {
        featureFlags: result.featureFlags,
        removedFeaturePaths: result.removedFeaturePaths,
        warnings: [...result.warnings, ...recipes.warnings, ...routeWarnings],
        nodeModulesFastPath: result.nodeModulesFastPath,
        recipes: recipes.applications.map((a) => ({
          recipeId: a.recipeId,
          recipeVersion: a.recipeVersion,
          instance: a.instance,
          title: a.title,
          description: a.description,
          files: a.files.length,
          requirementIds: [...new Set(a.requirements.map((r) => r.id))],
        })),
      },
    });
  } catch (err) {
    return finishStage(ctx, 'scaffold', 'failed', `The application could not be set up: ${err instanceof Error ? err.message : String(err)}`, started);
  }
}
