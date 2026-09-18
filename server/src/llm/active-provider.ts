/**
 * The provider SecureVibe uses right now, built fresh from Settings on every call: AI is used only when a key is
 * configured, the "Use AI" switch is on and SECUREVIBE_AI=off is not set.
 */
import { effectiveAiSettings, type SecureVibeConfig } from '../config.js';
import { createProvider, type CreateProviderOptions } from './provider.js';
import type { LlmProvider, LlmPurpose } from './types.js';

/** Builds the provider for one step: its service, its model and the effort, read fresh from Settings each time. */
export type ProviderFor = (purpose?: LlmPurpose) => LlmProvider;

export function providerFactory(config: Pick<SecureVibeConfig, 'settings' | 'aiDisabled'>, opts: CreateProviderOptions = {}): ProviderFor {
  return (purpose) => {
    const settings = effectiveAiSettings(config.settings.get(), purpose);
    return createProvider(
      {
        model: settings.model,
        aiService: settings.aiService,
        // (aiService is already the one this step uses: effectiveAiSettings resolved it from the purpose.)
        generationEffort: settings.generationEffort,
        reviewEffort: settings.reviewEffort,
        ...(config.aiDisabled || !settings.aiEnabled ? { forceProvider: 'null' as const } : {}),
      },
      opts,
    );
  };
}
