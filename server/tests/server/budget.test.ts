import { describe, expect, it } from 'vitest';
import { MIN_STAGE_BUDGET_USD, budgetExhaustedText, remainingBudgetUsd } from '../../src/pipeline/stage-helpers.js';
import type { PipelineCtx } from '../../src/pipeline/types.js';

const ctxWith = (cap: number, spent?: number) =>
  ({ spendingCapUsd: cap, run: { llmUsage: spent === undefined ? undefined : { estimatedCostUsd: spent } } }) as unknown as PipelineCtx;

describe('spending limit across AI steps', () => {
  it('gives each step only what is left of the whole build limit', () => {
    expect(remainingBudgetUsd(ctxWith(10))).toBe(10);
    expect(remainingBudgetUsd(ctxWith(10, 7.34))).toBeCloseTo(2.66);
    expect(remainingBudgetUsd(ctxWith(10, 12))).toBe(0);
    expect(remainingBudgetUsd(ctxWith(10, 9.8))).toBeLessThan(MIN_STAGE_BUDGET_USD);
  });

  it('explains the stop in plain words', () => {
    expect(budgetExhaustedText(ctxWith(10, 9.8))).toBe('the build has already used $9.80 of your $10.00 spending limit');
  });
});

describe('security notes in the build log', () => {
  it('says which rules matched and that the text was treated as data', async () => {
    const { securityEventLine } = await import('../../src/pipeline/stage-helpers.js');
    const line = securityEventLine({ event: 'agent.injection-flagged', outcome: 'flagged', detail: { tool: 'read_file', source: 'securevibe.manifest.json', rules: ['inj.llama-inst-token'] } });
    expect(line).toContain('securevibe.manifest.json');
    expect(line).toContain('inj.llama-inst-token');
    expect(line).toContain('only as data');
  });
});
