/**
 * `generate`: hands the brief and the confined tools to the Claude agent loop. A refusal ends the whole run
 * (CONTRACTS §9.5); any other incomplete outcome (budget, time limit, an internal error) leaves the run marked
 * failed but lets the rest of the pipeline still assess whatever code exists, with `incomplete: true`.
 */
import { randomUUID } from 'node:crypto';
import { join } from 'node:path';
import { writeFile } from 'node:fs/promises';
import type { RunFailure, StageResult } from '@shared/pipeline.js';
import { DEFAULT_BUDGETS, failureOptions, generateAppFlow, mergeUsage } from '../../integration.js';
import { buildGenerationBrief } from '../../generator/index.js';
import { markGeneratedFiles } from '../../generator/provenance.js';
import { refreshDerivedFiles } from '../../generator/scaffold.js';
import { makeRunCheck } from '../checks.js';
import { finishStage, securityEventLine, stageBudgetUsd, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';

export interface GenerateStageOutcome {
  result: StageResult;
  /** Set when generation refused outright: the run must stop immediately (no further stages). */
  hardStop?: RunFailure;
}

export async function runGenerate(ctx: PipelineCtx): Promise<GenerateStageOutcome> {
  const started = startStage(ctx, 'generate');
  if (!ctx.design || !ctx.manifest) {
    return { result: finishStage(ctx, 'generate', 'failed', 'The application was not ready to be written yet.', started) };
  }
  if (ctx.provider.name === 'null') {
    // Preview without AI is a supported way to build, not a failure: the scaffold already wrote a working app.
    const reason =
      'Skipped because SecureVibe is running without an Anthropic API key. Your app still has pages for every record you described; add a key and rebuild to have Claude write the rest of your features.';
    return { result: finishStage(ctx, 'generate', 'skipped', reason, started, { skippedReason: reason }) };
  }

  const brief = buildGenerationBrief(ctx.design, ctx.manifest, ctx.plan);
  // Usage events carry this step's running total; anything spent earlier in the build is added to it.
  const usageBefore = ctx.run.llmUsage;
  const correlationId = `gen-${ctx.run.id}-${randomUUID().slice(0, 8)}`;
  const budget = { ...DEFAULT_BUDGETS.generate, maxUsd: Math.min(DEFAULT_BUDGETS.generate.maxUsd, stageBudgetUsd(ctx, 'generate')) };

  const outcome = await generateAppFlow(ctx.provider, {
    appDir: ctx.appDir,
    design: ctx.design,
    manifest: ctx.manifest,
    brief,
    description: ctx.profile?.app.description,
    budget,
    runCheck: makeRunCheck(ctx),
    onEvent: (event) => {
      if (event.type === 'text' && event.text.trim()) ctx.bus.llm(event.text.trim().slice(0, 400));
      else if (event.type === 'tool_use') ctx.bus.log(`Claude is using ${event.tool}…`, 'generate');
      else if (event.type === 'security') ctx.log('generate', securityEventLine(event));
      else if (event.type === 'usage') ctx.run.llmUsage = usageBefore ? mergeUsage(usageBefore, event.usage) : event.usage;
    },
    abort: ctx.abort.signal,
    runId: ctx.run.id,
    projectId: ctx.project.id,
    correlationId,
    ...(ctx.settings.generationEffort ? { effort: ctx.settings.generationEffort } : {}),
  });

  ctx.acc.correlationIds.push(correlationId);
  ctx.acc.servedModels.push(...outcome.servedModels);
  if (!ctx.run.llmUsage || ctx.run.llmUsage === usageBefore) ctx.run.llmUsage = usageBefore ? mergeUsage(usageBefore, outcome.usage) : outcome.usage;

  if (ctx.provenance && outcome.filesTouched.length > 0) {
    ctx.provenance = markGeneratedFiles(ctx.provenance, ctx.appDir, outcome.filesTouched, 'ai-generated', { correlationId });
    await writeFile(join(ctx.appDir, 'securevibe.provenance.json'), `${JSON.stringify(ctx.provenance, null, 2)}\n`);
  }
  if (outcome.filesTouched.length > 0) {
    // New or changed routes must reach the route list and the generated docs before anything is checked.
    const refreshed = await refreshDerivedFiles({ appDir: ctx.appDir, projectDir: ctx.paths.dir, runId: ctx.run.id, manifest: ctx.manifest, provenance: ctx.provenance });
    if (refreshed.provenance) ctx.provenance = refreshed.provenance;
    for (const warning of refreshed.warnings) ctx.log('generate', warning);
  }

  const details = {
    summary: outcome.summary,
    filesTouched: outcome.filesTouched,
    iterations: outcome.iterations,
    servedModels: outcome.servedModels,
    pathDenials: outcome.pathDenials,
    injectionFlags: outcome.injectionFlags,
  };

  if (outcome.ok) {
    return { result: finishStage(ctx, 'generate', 'passed', outcome.summary || 'The application was written.', started, { details }) };
  }

  const failure: RunFailure = { stage: 'generate', message: outcome.message, options: failureOptions(outcome.status) };
  const result = finishStage(ctx, 'generate', 'failed', outcome.message, started, { details });

  if (outcome.status === 'refusal') {
    return { result, hardStop: failure };
  }
  ctx.run.incomplete = true;
  ctx.run.failure = failure;
  return { result };
}
