/**
 * Money and limits: the rate table, the per-call cost, the execution budgets (AISVS C9.1) and the estimate the
 * person sees before they approve a build.
 */
import { describe, expect, it } from 'vitest';
import {
  addUsage,
  BudgetTracker,
  CACHE_READ_FACTOR,
  CACHE_WRITE_FACTOR,
  costUsd,
  DEFAULT_BUDGETS,
  emptyLlmUsage,
  estimateCost,
  MODEL_RATES,
  ratesFor,
} from '../../src/llm/budget.js';
import { baselineProfile } from '../../src/llm/flows/quick-infer.js';
import { makeDesign } from './helpers.js';

const profile = baselineProfile({
  description: 'A repair tracker for a bike shop.',
  known: { audience: 'my-team', deploymentTarget: 'local-only', dataCategories: ['contact'] },
});

describe('rates and cost', () => {
  it('knows the current models and falls back safely', () => {
    expect(ratesFor('claude-opus-5')).toEqual({ inputPerMTok: 5, outputPerMTok: 25 });
    expect(ratesFor('claude-sonnet-5')).toEqual({ inputPerMTok: 2, outputPerMTok: 10 });
    expect(ratesFor('claude-opus-5-some-future-snapshot')).toEqual(MODEL_RATES['claude-opus-5']);
    expect(ratesFor('a-model-nobody-has-heard-of')).toEqual(MODEL_RATES['claude-opus-5']);
  });

  it('prices cache reads at a tenth and cache writes at a quarter more', () => {
    const million = { inputTokens: 1_000_000, outputTokens: 0, cacheReadTokens: 0, cacheWriteTokens: 0 };
    expect(costUsd('claude-opus-5', million)).toBeCloseTo(5, 6);
    expect(costUsd('claude-opus-5', { ...million, inputTokens: 0, cacheReadTokens: 1_000_000 })).toBeCloseTo(5 * CACHE_READ_FACTOR, 6);
    expect(costUsd('claude-opus-5', { ...million, inputTokens: 0, cacheWriteTokens: 1_000_000 })).toBeCloseTo(5 * CACHE_WRITE_FACTOR, 6);
    expect(costUsd('claude-opus-5', { ...million, inputTokens: 0, outputTokens: 1_000_000 })).toBeCloseTo(25, 6);
  });

  it('adds one call to a running total', () => {
    const total = emptyLlmUsage('anthropic', 'claude-opus-5');
    addUsage(total, {
      inputTokens: 100,
      outputTokens: 50,
      cacheReadTokens: 10,
      cacheWriteTokens: 5,
      costUsd: 0.5,
      servedModel: 'claude-sonnet-5',
      fallbackUsed: true,
      refused: true,
    });
    expect(total).toMatchObject({ calls: 1, inputTokens: 100, outputTokens: 50, refusals: 1, fallbacks: 1 });
    expect(total.estimatedCostUsd).toBeCloseTo(0.5, 6);
  });
});

describe('execution budgets', () => {
  const delta = (over: Partial<{ costUsd: number; outputTokens: number }> = {}) => ({
    inputTokens: 0,
    outputTokens: over.outputTokens ?? 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    costUsd: over.costUsd ?? 0,
    servedModel: 'claude-opus-5',
    fallbackUsed: false,
    refused: false,
  });

  it('stops on iterations, money, wall clock and output tokens, each with a plain-language reason', () => {
    const budget = { maxIterations: 2, maxUsd: 1, maxWallClockMs: 1000, maxOutputTokens: 100 };

    const iterations = new BudgetTracker(budget);
    iterations.iterations = 2;
    expect(iterations.check()).toMatchObject({ ok: false, reason: 'iterations' });

    const money = new BudgetTracker(budget);
    money.add(delta({ costUsd: 1.5 }));
    const moneyCheck = money.check();
    expect(moneyCheck.ok).toBe(false);
    if (!moneyCheck.ok) {
      expect(moneyCheck.reason).toBe('usd');
      expect(moneyCheck.message).toContain('spending limit of $1.00');
    }

    let now = 0;
    const clock = new BudgetTracker(budget, () => now);
    expect(clock.check().ok).toBe(true);
    now = 2000;
    expect(clock.check()).toMatchObject({ ok: false, reason: 'wall-clock' });

    const tokens = new BudgetTracker(budget);
    tokens.add(delta({ outputTokens: 200 }));
    expect(tokens.check()).toMatchObject({ ok: false, reason: 'output-tokens' });
  });

  it('ships sensible defaults for each kind of task', () => {
    for (const [name, budget] of Object.entries(DEFAULT_BUDGETS)) {
      expect(budget.maxIterations, name).toBeGreaterThan(0);
      expect(budget.maxUsd, name).toBeGreaterThan(0);
      expect(budget.maxWallClockMs, name).toBeGreaterThan(60_000);
    }
    expect(DEFAULT_BUDGETS.generate.maxUsd).toBeGreaterThan(DEFAULT_BUDGETS.fix.maxUsd);
  });
});

describe('cost estimate', () => {
  const settings = {
    model: 'claude-opus-5',
    generationEffort: 'high' as const,
    reviewEffort: 'medium' as const,
    defaultSpendingCapUsd: 15,
    maxFixRounds: 2,
  };

  it('gives a range, a time and a sentence the owner can read', () => {
    const estimate = estimateCost(profile, makeDesign().buildSpec, settings);
    expect(estimate.usdLow).toBeGreaterThan(0);
    expect(estimate.usdHigh).toBeGreaterThan(estimate.usdLow);
    expect(estimate.minutesHigh).toBeGreaterThan(estimate.minutesLow);
    expect(estimate.spendingCapUsd).toBe(15);
    expect(estimate.note).toContain('spending cap');
    expect(estimate.note).not.toMatch(/token|MTok/i);
  });

  it('costs more for a bigger application', () => {
    const bigger = structuredClone(profile);
    bigger.app.entities = Array.from({ length: 6 }, (_, i) => ({
      name: `record-${i + 1}`,
      label: `Record ${i + 1}`,
      description: '',
      access: 'all-signed-in' as const,
      fields: [],
    }));
    const small = estimateCost(profile, makeDesign().buildSpec, settings);
    const large = estimateCost(bigger, makeDesign().buildSpec, settings);
    expect(large.usdLow).toBeGreaterThan(small.usdLow);
    expect(large.minutesHigh).toBeGreaterThan(small.minutesHigh);
  });

  it('warns when the estimate can run past the cap', () => {
    const estimate = estimateCost(profile, makeDesign().buildSpec, { ...settings, defaultSpendingCapUsd: 1 });
    expect(estimate.note).toContain('above your cap');
  });
});
