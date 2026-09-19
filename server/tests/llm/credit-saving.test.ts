/** Keeping builds cheap: conversation caching, Save credits, the per-step budget split and the wrap-up notice. */
import { describe, expect, it } from 'vitest';
import { withConversationCache } from '../../src/llm/anthropic.js';
import { runAgentLoop, WRAP_UP_NOTICE, type AgentTurn } from '../../src/llm/agent-loop.js';
import { BudgetTracker, emptyLlmUsage } from '../../src/llm/budget.js';
import { DEFAULT_SETTINGS, effectiveAiSettings, SAVE_CREDITS_MODEL, SMALL_STEP_MODELS, SMALL_STEPS } from '../../src/config.js';
import { BUDGET_SHARES, stageBudgetUsd } from '../../src/pipeline/stage-helpers.js';
import type { PipelineCtx } from '../../src/pipeline/types.js';
import type { AgentRunRequest, AgentTool } from '../../src/llm/types.js';
import { z } from 'zod';

describe('conversation caching', () => {
  it('marks only the last block of the newest message', () => {
    const messages = withConversationCache([
      { role: 'user', content: [{ type: 'text', text: 'brief' }] },
      { role: 'assistant', content: [{ type: 'tool_use', id: 't1', name: 'list_files', input: {} }] },
      {
        role: 'user',
        content: [
          { type: 'tool_result', tool_use_id: 't1', content: 'a.ts' },
          { type: 'text', text: 'reminder' },
        ],
      },
    ]);
    const marked = messages.flatMap((m) => (typeof m.content === 'string' ? [] : m.content)).filter((b) => 'cache_control' in b && b.cache_control);
    expect(marked).toEqual([{ type: 'text', text: 'reminder', cache_control: { type: 'ephemeral' } }]);
  });

  it('leaves a conversation it cannot mark unchanged', () => {
    const messages = [{ role: 'assistant' as const, content: [{ type: 'tool_use' as const, id: 't', name: 'done', input: {} }] }];
    expect(withConversationCache(messages)).toBe(messages);
  });
});

describe('Save credits', () => {
  it('is on by default and uses the cheaper model, low effort and at most one fix round', () => {
    expect(DEFAULT_SETTINGS.saveCredits).toBe(true);
    expect(DEFAULT_SETTINGS.defaultSpendingCapUsd).toBe(5);
    const s = effectiveAiSettings({ ...DEFAULT_SETTINGS, model: 'claude-opus-5', generationEffort: 'max', reviewEffort: 'high', maxFixRounds: 3 });
    expect(s).toMatchObject({ model: SAVE_CREDITS_MODEL, generationEffort: 'low', reviewEffort: 'low', maxFixRounds: 1 });
    expect(effectiveAiSettings({ ...DEFAULT_SETTINGS, maxFixRounds: 0 }).maxFixRounds).toBe(0);
  });

  it('changes nothing when switched off', () => {
    const raw = { ...DEFAULT_SETTINGS, saveCredits: false, model: 'claude-opus-5', generationEffort: 'high' as const };
    expect(effectiveAiSettings(raw)).toBe(raw);
  });
});

describe('the small steps', () => {
  it('run on the cheap model of their service, whatever model is chosen for the rest', () => {
    const chosen = { ...DEFAULT_SETTINGS, saveCredits: false, model: 'claude-opus-5' };
    // Scoring a piece of text and rewriting wording in plain language are not judgement about the app.
    expect(effectiveAiSettings(chosen, 'classify').model).toBe(SMALL_STEP_MODELS.anthropic);
    expect(effectiveAiSettings(chosen, 'summarize').model).toBe(SMALL_STEP_MODELS.anthropic);
    // Writing and reviewing keep the model the owner chose.
    expect(effectiveAiSettings(chosen, 'generate').model).toBe('claude-opus-5');
    expect(effectiveAiSettings(chosen, 'ai-review').model).toBe('claude-opus-5');
    expect(effectiveAiSettings(chosen, 'plan').model).toBe('claude-opus-5');
  });

  it('follow the service that step was set to', () => {
    const viaGoogle = { ...DEFAULT_SETTINGS, aiService: 'google' as const, aiServiceFor: { write: 'default' as const, review: 'default' as const, questions: 'default' as const } };
    expect(effectiveAiSettings(viaGoogle, 'classify').model).toBe(SMALL_STEP_MODELS.google);
    const questionsOnOpenAi = { ...DEFAULT_SETTINGS, aiServiceFor: { write: 'default' as const, review: 'default' as const, questions: 'openai' as const } };
    expect(effectiveAiSettings(questionsOnOpenAi, 'classify')).toMatchObject({ aiService: 'openai', model: SMALL_STEP_MODELS.openai });
  });

  it('is a short list: only the steps that decide nothing about security', () => {
    expect([...SMALL_STEPS].sort()).toEqual(['classify', 'summarize']);
  });
});

describe('budget split', () => {
  const ctx = (spent: number, mode: 'full' | 'verify-only' = 'full', maxFixRounds = 1) =>
    ({
      spendingCapUsd: 5,
      settings: { maxFixRounds },
      run: { mode, llmUsage: { ...emptyLlmUsage('anthropic', 'm'), estimatedCostUsd: spent } },
    }) as unknown as PipelineCtx;

  it('keeps the review and fix shares away from writing the app', () => {
    expect(BUDGET_SHARES.generate + BUDGET_SHARES['ai-review'] + BUDGET_SHARES.fix).toBeCloseTo(1);
    expect(stageBudgetUsd(ctx(0), 'generate')).toBeCloseTo(2.75);
    expect(stageBudgetUsd(ctx(2.75), 'ai-review')).toBeCloseTo(1.5);
    expect(stageBudgetUsd(ctx(4.25), 'fix')).toBeCloseTo(0.75);
  });

  it('passes on what an earlier step did not use, and never more than is left', () => {
    expect(stageBudgetUsd(ctx(1), 'ai-review')).toBeCloseTo(3.25);
    expect(stageBudgetUsd(ctx(4.9), 'ai-review')).toBe(0);
    expect(stageBudgetUsd(ctx(0, 'verify-only'), 'ai-review')).toBeCloseTo(5);
    expect(stageBudgetUsd(ctx(0, 'full', 0), 'generate')).toBeCloseTo(3.5);
  });
});

describe('wrap-up notice', () => {
  it('is due at 70% of the money or 80% of the steps', () => {
    const t = new BudgetTracker({ maxIterations: 10, maxUsd: 1, maxWallClockMs: 60_000, maxOutputTokens: 1_000_000 });
    expect(t.nearlyUsed()).toBe(false);
    t.costUsd = 0.7;
    expect(t.nearlyUsed()).toBe(true);
    const u = new BudgetTracker({ maxIterations: 10, maxUsd: 1, maxWallClockMs: 60_000, maxOutputTokens: 1_000_000 });
    u.iterations = 8;
    expect(u.nearlyUsed()).toBe(true);
  });

  it('is sent once, after the turn that crossed the line', async () => {
    const tool: AgentTool = { name: 'list_files', description: 'list', inputSchema: z.object({}), run: async () => ({ content: 'a.ts' }) };
    const sent: string[][] = [];
    let n = 0;
    const turn = (cost: number): AgentTurn => ({
      blocks: [{ type: 'tool_use', id: `t${++n}`, name: 'list_files', input: {} }],
      stopReason: 'tool_use',
      usage: { inputTokens: 1, outputTokens: 1, cacheReadTokens: 0, cacheWriteTokens: 0, costUsd: cost, servedModel: 'm', fallbackUsed: false, refused: false },
    });
    const req: AgentRunRequest = {
      purpose: 'generate',
      system: [],
      user: 'go',
      tools: [tool],
      budget: { maxIterations: 4, maxUsd: 1, maxWallClockMs: 60_000, maxOutputTokens: 1_000_000 },
      correlationId: 'c',
      onEvent: () => undefined,
      abort: new AbortController().signal,
    };
    await runAgentLoop(req, {
      provider: 'scripted',
      model: 'm',
      runTurn: async ({ messages }) => {
        sent.push(messages.flatMap((m) => m.blocks.filter((b) => b.type === 'text').map((b) => (b as { text: string }).text)));
        return turn(0.3);
      },
    });
    const notices = sent.at(-1)!.filter((t) => t === WRAP_UP_NOTICE);
    expect(notices).toHaveLength(1);
    expect(sent[1]!.includes(WRAP_UP_NOTICE)).toBe(false);
    expect(sent[3]!.includes(WRAP_UP_NOTICE)).toBe(true);
  });
});
