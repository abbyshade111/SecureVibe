/**
 * `scaffold`: archives any previous `app/` to `app-v<N>/`, then copies and configures the hardened template
 * (generator/scaffold.ts) into the new `app/`.
 */
import type { StageResult } from '@shared/pipeline.js';
import { expandEntities, markGeneratedFiles, refreshDerivedFiles, scaffoldApp } from '../../generator/index.js';
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

    // Write a working feature for every record type the person described, so even a build without AI
    // produces a usable application and the generation agent only has to extend it.
    const expanded = await expandEntities({
      appDir: ctx.appDir,
      design: ctx.design,
      profile: ctx.profile,
      runId: ctx.run.id,
      log: (msg) => ctx.log('scaffold', msg),
    });
    if (expanded.filesWritten.length > 0) {
      ctx.provenance = markGeneratedFiles(ctx.provenance, ctx.appDir, expanded.filesWritten, 'expanded');
    }
    for (const warning of expanded.warnings) ctx.log('scaffold', warning);
    if (ctx.provenance) ctx.provenance = markGeneratedFiles(ctx.provenance, ctx.appDir, ['routes.manifest.json'], 'expanded');
    const refreshed = await refreshDerivedFiles({ appDir: ctx.appDir, projectDir: ctx.paths.dir, runId: ctx.run.id, manifest: ctx.manifest, provenance: ctx.provenance });
    if (refreshed.provenance) ctx.provenance = refreshed.provenance;
    const routeWarnings = refreshed.warnings;
    for (const warning of routeWarnings) ctx.log('scaffold', warning);

    const built = expanded.entities.length > 0 ? ` It already has pages and an interface for ${expanded.entities.map((e) => (e.label || e.name).toLowerCase()).join(', ')}.` : '';
    const summary = result.nodeModulesFastPath
      ? `The application folder is ready, with the packages already installed and the first administrator account created.${built}`
      : `The application folder is ready. Packages will be installed next.${built}`;
    return finishStage(ctx, 'scaffold', 'passed', summary, started, {
      details: {
        featureFlags: result.featureFlags,
        removedFeaturePaths: result.removedFeaturePaths,
        warnings: [...result.warnings, ...expanded.warnings, ...routeWarnings],
        nodeModulesFastPath: result.nodeModulesFastPath,
        expandedEntities: expanded.entities.map((e) => ({ name: e.name, table: e.table, routeBase: e.routeBase, files: e.files.length })),
      },
    });
  } catch (err) {
    return finishStage(ctx, 'scaffold', 'failed', `The application could not be set up: ${err instanceof Error ? err.message : String(err)}`, started);
  }
}
