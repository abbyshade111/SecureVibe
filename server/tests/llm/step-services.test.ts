/** Which AI service does which step: the settings resolution and the provider the factory hands each step. */
import { describe, expect, it } from 'vitest';
import { effectiveAiSettings, serviceForPurpose, SettingsSchema, stepGroupFor } from '../../src/config.js';
import { providerFactory } from '../../src/llm/active-provider.js';

const settings = (over: Record<string, unknown> = {}) => SettingsSchema.parse({ aiEnabled: true, saveCredits: false, model: 'claude-opus-5', ...over });

/** A stand-in for the settings store the factory reads on every call. */
function configWith(s: ReturnType<typeof settings>) {
  return { aiDisabled: false, settings: { get: () => s } } as never;
}

describe('step groups', () => {
  it('puts each AI step in the group the owner would expect', () => {
    expect(stepGroupFor('generate')).toBe('write');
    expect(stepGroupFor('fix')).toBe('write');
    expect(stepGroupFor('ai-review')).toBe('review');
    for (const p of ['plan', 'refine', 'peer-review', 'quick-infer', 'threat-model', 'classify', 'summarize'] as const) {
      expect(stepGroupFor(p), p).toBe('questions');
    }
  });
});

describe('serviceForPurpose', () => {
  it('uses the default service when a step says "default"', () => {
    const s = settings({ aiService: 'anthropic' });
    expect(serviceForPurpose(s, 'generate')).toBe('anthropic');
    expect(serviceForPurpose(s, 'ai-review')).toBe('anthropic');
    expect(serviceForPurpose(s)).toBe('anthropic');
  });

  it('sends only the steps that were changed to another service', () => {
    const s = settings({ aiService: 'anthropic', aiServiceFor: { write: 'default', review: 'google', questions: 'openai' } });
    expect(serviceForPurpose(s, 'generate')).toBe('anthropic');
    expect(serviceForPurpose(s, 'fix')).toBe('anthropic');
    expect(serviceForPurpose(s, 'ai-review')).toBe('google');
    expect(serviceForPurpose(s, 'plan')).toBe('openai');
  });
});

describe('effectiveAiSettings per step', () => {
  it('gives each step a model that belongs to its own service', () => {
    const s = settings({ aiService: 'anthropic', model: 'claude-opus-5', aiServiceFor: { write: 'default', review: 'google', questions: 'openai' } });
    expect(effectiveAiSettings(s, 'generate').model).toBe('claude-opus-5');
    expect(effectiveAiSettings(s, 'ai-review').model).toBe('gemini-2.5-pro');
    expect(effectiveAiSettings(s, 'plan').model).toBe('gpt-5');
  });

  it('Save credits picks the cheaper model of each step\'s service', () => {
    const s = settings({ saveCredits: true, aiService: 'anthropic', aiServiceFor: { write: 'default', review: 'google', questions: 'default' } });
    expect(effectiveAiSettings(s, 'generate').model).toBe('claude-sonnet-5');
    expect(effectiveAiSettings(s, 'ai-review').model).toBe('gemini-2.5-flash');
    expect(effectiveAiSettings(s, 'ai-review').reviewEffort).toBe('low');
  });
});

describe('providerFactory', () => {
  it('hands each step the provider for its own service when the keys are there', () => {
    const env = { ANTHROPIC_API_KEY: 'sk-ant-test', GOOGLE_API_KEY: 'g-test', OPENAI_API_KEY: 'sk-test' };
    const s = settings({ aiService: 'anthropic', aiServiceFor: { write: 'default', review: 'google', questions: 'openai' } });
    const provider = providerFactory(configWith(s), { env });
    expect(provider('generate').name).toBe('anthropic');
    expect(provider('ai-review').name).toBe('google');
    expect(provider('plan').name).toBe('openai');
    expect(provider().name).toBe('anthropic');
  });

  it('falls back to preview mode for a step whose service has no key', () => {
    const env = { ANTHROPIC_API_KEY: 'sk-ant-test' };
    const s = settings({ aiService: 'anthropic', aiServiceFor: { write: 'default', review: 'google', questions: 'default' } });
    const provider = providerFactory(configWith(s), { env });
    expect(provider('generate').name).toBe('anthropic');
    expect(provider('ai-review').name).toBe('null');
  });

  it('is preview mode everywhere when AI is switched off', () => {
    const s = settings({ aiEnabled: false, aiServiceFor: { write: 'default', review: 'google', questions: 'default' } });
    const provider = providerFactory(configWith(s), { env: { ANTHROPIC_API_KEY: 'sk-ant-test', GOOGLE_API_KEY: 'g-test' } });
    expect(provider('generate').name).toBe('null');
    expect(provider('ai-review').name).toBe('null');
  });
});
