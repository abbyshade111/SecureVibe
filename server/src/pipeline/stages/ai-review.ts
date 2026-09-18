/**
 * `ai-review`: Claude assesses the generated code against the applicable requirements, batched per chapter, with
 * every citation verified against the exact file text that was sent (DESIGN §13 item 10). Skipped honestly when
 * AI is not configured.
 */
import { readFileSync } from 'node:fs';
import { compileIgnore, isIgnored } from '../../scanners/sast/files.js';
import type { StageResult } from '@shared/pipeline.js';
import { aiReview, DEFAULT_BUDGETS, mergeUsage, toAiReviewResult, type ReviewFile, type RequirementBatch, type RequirementForReview } from '../../integration.js';
import { listFiles, sha256File } from '../../generator/files.js';
import { MIN_STAGE_BUDGET_USD, budgetExhaustedText, finishStage, stageBudgetUsd, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';

const MAX_FILES = 250;

/** Lower sorts first: security code, other source, views, configuration, then tests. */
function reviewPriority(relPath: string): number {
  if (/\.(test|spec)\.[cm]?[jt]sx?$/.test(relPath) || /(^|\/)tests?\//.test(relPath)) return 4;
  if (/(^|\/)(security|auth|authz)(\/|\.)/.test(relPath) || /(^|\/)(app|server|main|process|middleware|token|csrf)\.[cm]?[jt]sx?$/.test(relPath)) return 0;
  if (/(^|\/)src\//.test(relPath) && /\.[cm]?[jt]sx?$/.test(relPath)) return 1;
  if (/\.ejs$/.test(relPath)) return 2;
  return 3;
}

/** The files the AI review may read: the scan's own exclusions apply, and only code, views and key config. */
function collectFiles(appDir: string, extraIgnore: string[]): ReviewFile[] {
  const ignore = compileIgnore(extraIgnore);
  const files = listFiles(appDir)
    .filter((f) => !f.relPath.startsWith('node_modules/') && !isIgnored(f.relPath, ignore))
    .filter((f) => /\.(ts|tsx|ejs)$/.test(f.relPath) || /(^|\/)(package\.json|securevibe\.manifest\.json)$/.test(f.relPath))
    .sort((a, b) => reviewPriority(a.relPath) - reviewPriority(b.relPath) || a.relPath.localeCompare(b.relPath));
  return files.slice(0, MAX_FILES).map((f) => {
    let content = '';
    try {
      content = readFileSync(f.absPath, 'utf8');
    } catch {
      content = '';
    }
    return { path: f.relPath, sha256: sha256File(f.absPath) ?? '', content };
  });
}

function buildBatches(ctx: PipelineCtx): RequirementBatch[] {
  if (!ctx.design) return [];
  const applicability = ctx.design.applicability;
  const ids: { id: string; standard: 'asvs' | 'aisvs' | 'aisvs-appendix-c' }[] = [
    ...applicability.asvs.applicable.map((id) => ({ id, standard: 'asvs' as const })),
    ...(applicability.aisvs.enabled ? applicability.aisvs.applicable.map((id) => ({ id, standard: 'aisvs' as const })) : []),
    ...applicability.appendixC.applicable.map((id) => ({ id, standard: 'aisvs-appendix-c' as const })),
  ];
  const byChapter = new Map<string, RequirementBatch>();
  for (const { id, standard } of ids) {
    if (ctx.aiReviewSkip?.has(id)) continue;
    const frameworkStandard = standard === 'aisvs-appendix-c' ? 'aisvs' : standard;
    const info = ctx.frameworks.getRequirement(id);
    if (!info) continue;
    const key = `${standard}:${info.chapterId}`;
    let batch = byChapter.get(key);
    if (!batch) {
      batch = { chapterId: info.chapterId, chapterName: info.chapterName, standard, requirements: [] };
      byChapter.set(key, batch);
    }
    const plain = ctx.knowledge.requirementsPlain[id]?.plain;
    const req: RequirementForReview = { id: info.id, description: info.description, level: info.level, ...(plain ? { plain } : {}) };
    batch.requirements.push(req);
    void frameworkStandard;
  }
  return [...byChapter.values()];
}

/** Why some requirements were not reviewed, in one short sentence (spending limit, cut-off or failed calls). */
function notReviewedNote(batches: { ok: boolean; message: string }[]): string {
  const failed = batches.filter((b) => !b.ok);
  if (failed.length === 0) return '';
  const limit = failed.filter((b) => /spending limit/.test(b.message)).length;
  const stopped = failed.filter((b) => b.message.startsWith('Not reviewed: '));
  const other = failed.length - limit - stopped.length;
  const parts = [
    ...(limit > 0 ? [`${limit} call(s) were not made because of the spending limit`] : []),
    ...(stopped.length > 0 ? [`${stopped.length} call(s) were not made: ${stopped[0]!.message.slice('Not reviewed: '.length).replace(/\.$/, '')}`] : []),
    ...(other > 0 ? [`${other} call(s) did not give a usable answer`] : []),
  ];
  return ` ${parts.join('; ')}.`;
}

export async function runAiReviewStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'ai-review');
  if (!ctx.design) {
    return finishStage(ctx, 'ai-review', 'skipped', 'The design was not available, so nothing could be reviewed.', started, { skippedReason: 'no design' });
  }
  const provider = ctx.providerFor('ai-review');
  if (provider.name === 'null') {
    return finishStage(ctx, 'ai-review', 'skipped', 'AI is not configured, so no AI review was performed. Nothing in this run was assessed by AI.', started, {
      skippedReason: 'AI is not configured (preview mode)',
    });
  }

  const files = collectFiles(ctx.appDir, ctx.extraIgnore ?? []);
  const requirements = buildBatches(ctx);
  if (requirements.length === 0) {
    return finishStage(ctx, 'ai-review', 'skipped', 'No requirements applied to this build, so there was nothing to review.', started, { skippedReason: 'no applicable requirements' });
  }

  const remaining = stageBudgetUsd(ctx, 'ai-review');
  if (remaining < MIN_STAGE_BUDGET_USD) {
    const reason = `Skipped because ${budgetExhaustedText(ctx)}. Nothing in this run was assessed by AI.`;
    return finishStage(ctx, 'ai-review', 'skipped', reason, started, { skippedReason: 'spending limit reached' });
  }

  const outcome = await aiReview(provider, {
    appDir: ctx.appDir,
    files,
    requirements,
    design: ctx.design,
    budget: { ...DEFAULT_BUDGETS.review, maxUsd: Math.min(DEFAULT_BUDGETS.review.maxUsd, remaining) },
    projectId: ctx.project.id,
    runId: ctx.run.id,
    ...(ctx.settings.reviewEffort ? { effort: ctx.settings.reviewEffort } : {}),
    abort: ctx.abort.signal,
    onBatch: (info) => ctx.bus.llm(`Reviewed ${info.chapterId}: ${info.message}`),
  });

  ctx.run.llmUsage = ctx.run.llmUsage ? mergeUsage(ctx.run.llmUsage, outcome.usage) : outcome.usage;
  ctx.acc.findings.push(...outcome.findings);
  ctx.acc.correlationIds.push(...outcome.correlationIds);
  ctx.acc.servedModels.push(...(outcome.model ? [outcome.model] : []));

  ctx.aiReviewResult = toAiReviewResult(outcome);

  const requested = requirements.reduce((n, b) => n + b.requirements.length, 0);
  const skippedNote = ctx.aiReviewSkip?.size
    ? `${ctx.aiReviewSkip.size} requirement(s) already verified by automated checks were not sent to the AI (to save cost). `
    : '';
  // Mostly unreviewed (spending limit, no credit, failed calls) is a warning, not a pass.
  const status = outcome.performed
    ? outcome.assessments.length > 0 && outcome.reviewedRequirementIds.length * 2 >= requested
      ? 'passed'
      : 'warning'
    : 'skipped';
  const summary = outcome.performed
    ? `${skippedNote}Claude reviewed ${outcome.reviewedRequirementIds.length} of ${requested} requirement(s) and cited ${outcome.totalCitations} place(s) in the code (${outcome.unverifiedCitations} citation(s) could not be verified).${notReviewedNote(outcome.batches)}`
    : (outcome.skippedReason ?? (ctx.abort.signal.aborted ? 'The AI review was stopped because the build was cancelled; nothing it had started counts as evidence.' : 'The AI review did not run.'));
  return finishStage(ctx, 'ai-review', status, summary, started, {
    ...(outcome.skippedReason ? { skippedReason: outcome.skippedReason } : {}),
    details: { assessments: outcome.assessments.length, hallucinationRate: outcome.hallucinationRate, batches: outcome.batches },
  });
}
