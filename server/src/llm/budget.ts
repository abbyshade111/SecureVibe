/**
 * Execution budgets (AISVS C9.1), the model rate table, cost accounting and the pre-build cost estimate.
 * Rates are US dollars per million tokens. Cache reads cost 10% of the input rate, cache writes 125%.
 */
import type { BuildSpec } from '@shared/design.js';
import type { CostEstimate, LlmUsage } from '@shared/pipeline.js';
import type { DesignProfile } from '@shared/profile.js';
import type { Budget, Effort, UsageDelta } from './types.js';

export interface ModelRates {
  inputPerMTok: number;
  outputPerMTok: number;
}

export const DEFAULT_MODEL = 'claude-opus-5';

export const MODEL_RATES: Record<string, ModelRates> = {
  'claude-opus-5': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-opus-4-8': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-opus-4-7': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-opus-4-6': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-opus-4-5': { inputPerMTok: 5, outputPerMTok: 25 },
  'claude-sonnet-5': { inputPerMTok: 2, outputPerMTok: 10 },
  'claude-sonnet-4-6': { inputPerMTok: 3, outputPerMTok: 15 },
  'claude-sonnet-4-5': { inputPerMTok: 3, outputPerMTok: 15 },
  'claude-haiku-4-5': { inputPerMTok: 1, outputPerMTok: 5 },
  'claude-fable-5-1': { inputPerMTok: 10, outputPerMTok: 50 },
  'claude-fable-5': { inputPerMTok: 10, outputPerMTok: 50 },
  // Other services (list prices when added; a build never passes its spending limit whatever the exact rate).
  'gpt-5-mini': { inputPerMTok: 0.25, outputPerMTok: 2 },
  'gpt-5': { inputPerMTok: 1.25, outputPerMTok: 10 },
  'gpt-4.1': { inputPerMTok: 2, outputPerMTok: 8 },
  'gemini-2.5-flash': { inputPerMTok: 0.3, outputPerMTok: 2.5 },
  'gemini-2.5-pro': { inputPerMTok: 1.25, outputPerMTok: 10 },
};

export const CACHE_READ_FACTOR = 0.1;
export const CACHE_WRITE_FACTOR = 1.25;

/** Exact match first, then the longest known id that prefixes the served model (dated snapshots), else opus-5 rates. */
export function ratesFor(model: string): ModelRates {
  const exact = MODEL_RATES[model];
  if (exact) return exact;
  let best: string | undefined;
  for (const id of Object.keys(MODEL_RATES)) {
    if (model.startsWith(id) && (!best || id.length > best.length)) best = id;
  }
  return best ? MODEL_RATES[best]! : MODEL_RATES[DEFAULT_MODEL]!;
}

export interface TokenCounts {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
}

export function costUsd(model: string, t: TokenCounts): number {
  const r = ratesFor(model);
  const usd =
    (t.inputTokens * r.inputPerMTok +
      t.cacheReadTokens * r.inputPerMTok * CACHE_READ_FACTOR +
      t.cacheWriteTokens * r.inputPerMTok * CACHE_WRITE_FACTOR +
      t.outputTokens * r.outputPerMTok) /
    1_000_000;
  return Math.round(usd * 1_000_000) / 1_000_000;
}

export const DEFAULT_BUDGETS: Record<'generate' | 'fix' | 'review', Budget> = {
  generate: { maxIterations: 60, maxUsd: 25, maxWallClockMs: 45 * 60_000, maxOutputTokens: 400_000 },
  fix: { maxIterations: 15, maxUsd: 8, maxWallClockMs: 15 * 60_000, maxOutputTokens: 120_000 },
  review: { maxIterations: 1, maxUsd: 10, maxWallClockMs: 10 * 60_000, maxOutputTokens: 60_000 },
};

export function emptyLlmUsage(provider: string, model: string): LlmUsage {
  return {
    provider,
    model,
    calls: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    estimatedCostUsd: 0,
    refusals: 0,
    fallbacks: 0,
  };
}

/** Adds one call's usage to a running total (mutates and returns `total`). */
export function addUsage(total: LlmUsage, delta: UsageDelta): LlmUsage {
  total.calls += 1;
  total.inputTokens += delta.inputTokens;
  total.outputTokens += delta.outputTokens;
  total.cacheReadTokens += delta.cacheReadTokens;
  total.cacheWriteTokens += delta.cacheWriteTokens;
  total.estimatedCostUsd = Math.round((total.estimatedCostUsd + delta.costUsd) * 1_000_000) / 1_000_000;
  if (delta.refused) total.refusals += 1;
  if (delta.fallbackUsed) total.fallbacks += 1;
  return total;
}

export function mergeUsage(into: LlmUsage, other: LlmUsage): LlmUsage {
  into.calls += other.calls;
  into.inputTokens += other.inputTokens;
  into.outputTokens += other.outputTokens;
  into.cacheReadTokens += other.cacheReadTokens;
  into.cacheWriteTokens += other.cacheWriteTokens;
  into.estimatedCostUsd = Math.round((into.estimatedCostUsd + other.estimatedCostUsd) * 1_000_000) / 1_000_000;
  into.refusals += other.refusals;
  into.fallbacks += other.fallbacks;
  return into;
}

export type BudgetStopReason = 'iterations' | 'usd' | 'wall-clock' | 'output-tokens';

export type BudgetCheck = { ok: true } | { ok: false; reason: BudgetStopReason; message: string };

/** Tracks one agent run against its budget. `check()` is consulted before every model turn. */
export class BudgetTracker {
  iterations = 0;
  costUsd = 0;
  outputTokens = 0;
  readonly startedAt: number;

  constructor(
    readonly budget: Budget,
    now: () => number = Date.now,
  ) {
    this.now = now;
    this.startedAt = now();
  }

  private readonly now: () => number;

  add(delta: UsageDelta): void {
    this.costUsd = Math.round((this.costUsd + delta.costUsd) * 1_000_000) / 1_000_000;
    this.outputTokens += delta.outputTokens;
  }

  elapsedMs(): number {
    return this.now() - this.startedAt;
  }

  remainingUsd(): number {
    return Math.max(0, this.budget.maxUsd - this.costUsd);
  }

  /** True once 70% of the money or 80% of the working steps are used. */
  nearlyUsed(): boolean {
    return this.costUsd >= this.budget.maxUsd * 0.7 || this.iterations >= Math.floor(this.budget.maxIterations * 0.8);
  }

  check(): BudgetCheck {
    const b = this.budget;
    if (this.iterations >= b.maxIterations) {
      return {
        ok: false,
        reason: 'iterations',
        message: `The AI reached the limit of ${b.maxIterations} working steps for this task.`,
      };
    }
    if (this.costUsd >= b.maxUsd) {
      return {
        ok: false,
        reason: 'usd',
        message: `The AI reached the spending limit of $${b.maxUsd.toFixed(2)} for this task.`,
      };
    }
    if (this.elapsedMs() >= b.maxWallClockMs) {
      return {
        ok: false,
        reason: 'wall-clock',
        message: `The AI reached the time limit of ${Math.round(b.maxWallClockMs / 60_000)} minutes for this task.`,
      };
    }
    if (this.outputTokens >= b.maxOutputTokens) {
      return {
        ok: false,
        reason: 'output-tokens',
        message: 'The AI reached the limit on how much text it may produce for this task.',
      };
    }
    return { ok: true };
  }
}

export interface EstimateSettings {
  model: string;
  generationEffort: Effort;
  reviewEffort: Effort;
  defaultSpendingCapUsd: number;
  maxFixRounds: number;
  /** Checking an app that already exists: only the code review uses AI. */
  reviewOnly?: boolean;
}

/** How many requirements one AI review call covers at each effort (reasoning shares the answer's room). */
export const REQUIREMENTS_PER_CALL_BY_EFFORT: Record<Effort, number> = { low: 10, medium: 5, high: 2, xhigh: 1, max: 1 };

const OUTPUT_FACTOR: Record<Effort, number> = { low: 1, medium: 1.5, high: 2.2, xhigh: 3, max: 4 };

/**
 * Pre-build estimate shown before the person approves the build, priced at the model the build will use.
 *
 * Writing the app is a conversation: every working step re-sends everything so far, which is read from the prompt
 * cache (a tenth of the price) apart from the newest part. The code review sends the app's files once (cached) and
 * then a group of requirements per call. The range is deliberately wide; the spending limit is the real guarantee.
 */
export function estimateCost(profile: DesignProfile, buildSpec: BuildSpec, settings: EstimateSettings): CostEstimate {
  const entities = profile.app.entities.length;
  const features = Object.values(buildSpec.features).filter((v) => v === true).length;
  const genOut = OUTPUT_FACTOR[settings.generationEffort] ?? 1;
  const reviewOut = OUTPUT_FACTOR[settings.reviewEffort] ?? 1;

  // Writing the app: `steps` turns; the conversation starts at ~14k tokens and grows by ~4k per turn.
  const gen = (steps: number) => {
    if (steps === 0) return 0;
    const start = 14_000;
    const growth = 4_000;
    let cacheRead = 0;
    for (let i = 1; i < steps; i++) cacheRead += start + growth * (i - 1);
    return costUsd(settings.model, {
      inputTokens: 1_500 * steps,
      cacheReadTokens: cacheRead,
      cacheWriteTokens: start + growth * steps,
      outputTokens: Math.round(1_600 * genOut * steps),
    });
  };
  const genStepsLow = settings.reviewOnly ? 0 : 12 + 3 * entities + Math.ceil(features / 2);
  const genStepsHigh = Math.round(genStepsLow * 1.8);

  // Code review: the app's files (~45k tokens plus ~6k per record type) once, then one call per requirement group.
  const files = 45_000 + 6_000 * entities;
  const requirements = 120 + (buildSpec.features.ai ? 60 : 0);
  const calls = Math.ceil(requirements / (REQUIREMENTS_PER_CALL_BY_EFFORT[settings.reviewEffort] ?? 10));
  const review = (share: number) =>
    costUsd(settings.model, {
      inputTokens: 1_500 * calls,
      cacheReadTokens: files * (calls - 1),
      cacheWriteTokens: files,
      outputTokens: Math.round(4_500 * reviewOut * calls * share),
    });

  const fixSteps = settings.reviewOnly ? 0 : settings.maxFixRounds * 8;
  const fix = fixSteps > 0 ? costUsd(settings.model, { inputTokens: 1_500 * fixSteps, cacheReadTokens: 60_000 * fixSteps, cacheWriteTokens: 6_000 * fixSteps, outputTokens: 1_600 * genOut * fixSteps }) : 0;

  const cap = settings.defaultSpendingCapUsd;
  const usdLow = round2(gen(genStepsLow) + review(0.7));
  const usdHigh = round2(gen(genStepsHigh) + review(1) + fix);

  const minutesLow = Math.max(4, Math.round(genStepsLow * 0.4 + calls * 0.3 + 3));
  const minutesHigh = Math.max(minutesLow + 5, Math.round(genStepsHigh * 0.9 + calls * 0.8 + fixSteps * 0.8 + 6));

  const shown = (n: number) => `$${Math.min(n, cap).toFixed(2)}`;
  let note = settings.reviewOnly
    ? `We expect the check to use between ${shown(usdLow)} and ${shown(usdHigh)} of AI-service credit with ${settings.model} ` +
      `for the AI code review, and take ${minutesLow} to ${minutesHigh} minutes. It never goes past your spending cap of $${cap.toFixed(2)}.`
    : `We expect the build to use between ${shown(usdLow)} and ${shown(usdHigh)} of AI-service credit with ${settings.model} ` +
      `and take ${minutesLow} to ${minutesHigh} minutes. It never goes past your spending cap of $${cap.toFixed(2)}: ` +
      'writing the app may use up to 55% of it, and the rest is kept for the code review and the fixes.';
  if (usdHigh > cap) {
    note +=
      ' The high end of the estimate is above your cap, so for a large app Claude may be asked to finish early and leave some features for later; you can raise the cap below.';
  }
  return { minutesLow, minutesHigh, usdLow: Math.min(usdLow, cap), usdHigh: Math.min(usdHigh, cap), spendingCapUsd: cap, note };
}

function round2(n: number): number {
  return Math.round(n * 100) / 100;
}
