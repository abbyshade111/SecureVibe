/**
 * Which provider SecureVibe picks, what preview mode says, and how a structured call handles the answers that are
 * not a result: a refusal, a truncated answer, malformed output and a fallback model.
 */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { costUsd } from '../../src/llm/budget.js';
import { NullProvider, PREVIEW_MESSAGE } from '../../src/llm/null.js';
import { createProvider, hasCredentials, providerStatus } from '../../src/llm/provider.js';
import { ScriptedProvider } from '../../src/llm/scripted.js';
import { ThreatModelOutputSchema } from '../../src/llm/flows/threat-model.js';
import { QuickInferOutputSchema } from '../../src/llm/flows/quick-infer.js';
import { FIXTURE_DIR, TEST_BUDGET } from './helpers.js';

const emptyEnv: NodeJS.ProcessEnv = {};

describe('provider selection', () => {
  it('only looks at whether a credential variable is set', () => {
    expect(hasCredentials(emptyEnv)).toBe(false);
    expect(hasCredentials({ ANTHROPIC_API_KEY: '' })).toBe(false);
    expect(hasCredentials({ ANTHROPIC_API_KEY: '   ' })).toBe(false);
    expect(hasCredentials({ ANTHROPIC_API_KEY: 'sk-ant-test' })).toBe(true);
    expect(hasCredentials({ ANTHROPIC_AUTH_TOKEN: 'oauth-token' })).toBe(true);
  });

  it('falls back to preview mode without a credential', () => {
    const provider = createProvider({}, { env: emptyEnv });
    expect(provider.name).toBe('null');
    const status = providerStatus(provider);
    expect(status.previewMode).toBe(true);
    expect(status.configured).toBe(false);
    expect(status.message).toContain('without an Anthropic API key');
  });

  it('uses the scripted provider when a scenario folder is configured', () => {
    const provider = createProvider({ scriptedScenarioDir: FIXTURE_DIR }, { env: emptyEnv });
    expect(provider.name).toBe('scripted');
    expect(providerStatus(provider).message).toContain('testing only');
  });

  it('uses the Anthropic provider when a credential is present', () => {
    const provider = createProvider({ model: 'claude-opus-5' }, { env: { ANTHROPIC_API_KEY: 'sk-ant-test-key' } });
    expect(provider.name).toBe('anthropic');
    expect(provider.model).toBe('claude-opus-5');
    expect(providerStatus(provider).configured).toBe(true);
  });

  it('honours forceProvider', () => {
    expect(createProvider({ forceProvider: 'null' }, { env: { ANTHROPIC_API_KEY: 'sk-ant-x' } }).name).toBe('null');
    expect(createProvider({ forceProvider: 'anthropic' }, { env: emptyEnv }).name).toBe('anthropic');
  });
});

describe('preview mode', () => {
  it('says so instead of pretending', async () => {
    const provider = new NullProvider('claude-opus-5');
    const structured = await provider.structured({
      purpose: 'quick-infer',
      system: [{ text: 'role' }],
      user: 'hello',
      schema: z.strictObject({ a: z.string() }),
      effort: 'medium',
      maxTokens: 1000,
      correlationId: 'c1',
      projectId: 'p1',
    });
    expect(structured.ok).toBe(false);
    if (!structured.ok) {
      expect(structured.reason).toBe('error');
      expect(structured.message).toBe(PREVIEW_MESSAGE);
    }

    const run = await provider.agentRun({
      purpose: 'generate',
      system: [{ text: 'role' }],
      user: 'build it',
      tools: [],
      budget: TEST_BUDGET,
      correlationId: 'c2',
      onEvent: () => {},
      abort: new AbortController().signal,
    });
    expect(run.status).toBe('skipped');
    expect(run.ok).toBe(false);
    expect(run.usage.calls).toBe(0);
  });
});

describe('structured calls', () => {
  const call = <T>(scenario: string, schema: z.ZodType<T>, purpose: 'quick-infer' | 'threat-model' = 'quick-infer') =>
    new ScriptedProvider({ dir: FIXTURE_DIR, scenario }).structured({
      purpose,
      system: [{ text: 'role', cache: true }],
      user: 'do the thing',
      schema,
      effort: 'medium',
      maxTokens: 8000,
      correlationId: 'c-structured',
      projectId: 'p1',
    });

  it('rejects output that is not the shape SecureVibe asked for', async () => {
    const result = await call('invalid-json-output', QuickInferOutputSchema);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('invalid_output');
      expect(result.message).toContain('did not have the shape');
    }
  });

  it('reports a refusal with its category and does not parse the content', async () => {
    const result = await call('refusal-before-output', QuickInferOutputSchema);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('refusal');
      expect(result.category).toBe('cyber');
      expect(result.usage.refused).toBe(true);
    }
  });

  it('records the model that actually served a fallback answer, and prices it at that model', async () => {
    const result = await call('fallback-served', ThreatModelOutputSchema, 'threat-model');
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.servedModel).toBe('claude-sonnet-5');
      expect(result.usage.fallbackUsed).toBe(true);
      const expected = costUsd('claude-sonnet-5', {
        inputTokens: 8000,
        outputTokens: 900,
        cacheReadTokens: 4000,
        cacheWriteTokens: 0,
      });
      expect(result.usage.costUsd).toBeCloseTo(expected, 6);
      // Cheaper than pricing the same tokens at the requested model's rate.
      expect(result.usage.costUsd).toBeLessThan(
        costUsd('claude-opus-5', { inputTokens: 8000, outputTokens: 900, cacheReadTokens: 4000, cacheWriteTokens: 0 }),
      );
    }
  });

  it('explains a missing scenario instead of throwing', async () => {
    const result = await call('does-not-exist', QuickInferOutputSchema);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.message).toContain('no scenario file');
  });
});
