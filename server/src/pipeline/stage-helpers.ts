/**
 * Shared plumbing every stage function uses: consistent StageResult construction, bus events, the per-stage log
 * file, and turning a scanner's ScanResult into a StageResult while folding its findings/evidence/coverage into
 * the run's accumulator.
 */
import { STAGE_DESCRIPTIONS, type StageId, type StageResult, type StageStatus } from '@shared/pipeline.js';
import type { ScanResult } from '../integration.js';
import { appendStageLog } from './persist.js';
import type { PipelineCtx } from './types.js';

export function startStage(ctx: PipelineCtx, stage: StageId): Date {
  const started = new Date();
  ctx.bus.stage(stage, 'running', STAGE_DESCRIPTIONS[stage].running);
  ctx.log(stage, STAGE_DESCRIPTIONS[stage].running);
  return started;
}

export interface FinishStageOptions {
  skippedReason?: string;
  details?: unknown;
  round?: number;
}

export function finishStage(ctx: PipelineCtx, stage: StageId, status: StageStatus, summary: string, started: Date, opts: FinishStageOptions = {}): StageResult {
  const finished = new Date();
  const logFile = appendStageLog(ctx.store, ctx.project.id, ctx.run.id, stage, summary);
  const result: StageResult = {
    id: stage,
    status,
    startedAt: started.toISOString(),
    finishedAt: finished.toISOString(),
    durationMs: finished.getTime() - started.getTime(),
    summary,
    round: opts.round ?? 0,
    logFile,
    ...(opts.skippedReason ? { skippedReason: opts.skippedReason } : {}),
    ...(opts.details !== undefined ? { details: opts.details } : {}),
  };
  ctx.bus.stage(stage, status, summary, opts.details);
  ctx.log(stage, summary);
  return result;
}

export function skipStage(ctx: PipelineCtx, stage: StageId, reason: string): StageResult {
  const started = new Date();
  return finishStage(ctx, stage, 'skipped', reason, started, { skippedReason: reason });
}

/** Folds a scanner's result into the run's findings/evidence/coverage and returns the matching StageResult. */
export function absorbScanResult(ctx: PipelineCtx, stage: StageId, started: Date, result: ScanResult): StageResult {
  const excluded = ctx.excludedChecks;
  const findings = excluded ? result.findings.filter((f) => !excluded.has(f.ruleId)) : result.findings;
  const evidence = excluded ? result.evidence.filter((e) => !excluded.has(e.ref)) : result.evidence;
  ctx.acc.findings.push(...findings);
  ctx.acc.evidence.push(...evidence);
  ctx.acc.coverage.push(result.coverage);
  const dropped = new Set([
    ...result.findings.filter((f) => !findings.includes(f)).map((f) => f.ruleId),
    ...result.evidence.filter((e) => !evidence.includes(e)).map((e) => e.ref),
  ]).size;
  if (dropped === 0) return finishStage(ctx, stage, result.status, result.summary, started, { details: result.details });
  // The scanner's own counts include the checks left out; say so, and do not fail the step on them alone.
  const status = findings.length === 0 && (result.status === 'failed' || result.status === 'warning') ? 'passed' : result.status;
  // Rules assume a kind of target: an uploaded app is not built from our template, and SecureVibe itself is a
  // build tool, not a generated application. Say which, so the reader knows why the results were left out.
  const why = ctx.excludedChecksReason ?? 'only apply to apps built by SecureVibe';
  const summary = `${result.summary} (Includes ${dropped} check(s) that ${why}; their results were left out.)`;
  return finishStage(ctx, stage, status, summary, started, { details: result.details });
}

/** True once install has been attempted and did not succeed — typecheck/unit-tests/dast are skipped then (CONTRACTS §9.5). */
export function installFailed(ctx: PipelineCtx): boolean {
  const install = ctx.run.stages.find((s) => s.id === 'install');
  return install !== undefined && install.status !== 'passed' && install.status !== 'skipped';
}

/** Below this, an AI step is not started: it could not do useful work before hitting the limit. */
export const MIN_STAGE_BUDGET_USD = 0.5;

/**
 * What is left of the spending cap the person approved for this whole build. Every AI step gets at most this
 * much, so the steps together never go past the cap.
 */
export function remainingBudgetUsd(ctx: PipelineCtx): number {
  return Math.max(0, ctx.spendingCapUsd - (ctx.run.llmUsage?.estimatedCostUsd ?? 0));
}

/**
 * How the spending limit is shared between the AI steps of one build. A step may use its own share plus whatever
 * earlier steps left unused, but never the shares kept for the steps after it, so writing the app cannot use up the
 * money the code review and the fixes need, and the whole build finishes within the limit.
 */
export const BUDGET_SHARES = { generate: 0.55, 'ai-review': 0.3, fix: 0.15 } as const;

export function stageBudgetUsd(ctx: PipelineCtx, stage: keyof typeof BUDGET_SHARES): number {
  const fixRuns = ctx.run.mode !== 'verify-only' && ctx.settings.maxFixRounds > 0;
  const later = stage === 'generate' ? BUDGET_SHARES['ai-review'] + (fixRuns ? BUDGET_SHARES.fix : 0) : stage === 'ai-review' && fixRuns ? BUDGET_SHARES.fix : 0;
  return Math.max(0, remainingBudgetUsd(ctx) - ctx.spendingCapUsd * later);
}

export function budgetExhaustedText(ctx: PipelineCtx): string {
  const spent = ctx.run.llmUsage?.estimatedCostUsd ?? 0;
  return `the build has already used $${spent.toFixed(2)} of your $${ctx.spendingCapUsd.toFixed(2)} spending limit`;
}

/** One log line for a tool-layer security event (a flagged file read, a denied path), so the build log explains it. */
export function securityEventLine(event: { event: string; outcome: string; detail: Record<string, unknown> }): string {
  const d = event.detail;
  if (event.event === 'agent.injection-flagged') {
    const rules = Array.isArray(d['rules']) ? (d['rules'] as unknown[]).join(', ') : 'unknown rules';
    return `Text the AI read (${String(d['source'] ?? d['tool'] ?? 'a tool result')}) matched prompt-injection rules (${rules}); it was ${event.outcome} and passed to the AI only as data.`;
  }
  if (event.event === 'agent.path-denied') return `The AI tried to use a path it is not allowed to (${String(d['path'] ?? 'unknown')}); the request was ${event.outcome}.`;
  return `AI tool problem (${event.event}, ${event.outcome}).`;
}
