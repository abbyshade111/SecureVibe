/**
 * The provider SecureVibe uses right now, built fresh from Settings on every call: AI is used only when a key is
 * configured, the "Use AI" switch is on and SECUREVIBE_AI=off is not set.
 */
import { effectiveAiSettings, type SecureVibeConfig } from '../config.js';
import { createProvider, type CreateProviderOptions } from './provider.js';
import type { LlmProvider } from './types.js';

export function providerFactory(config: Pick<SecureVibeConfig, 'settings' | 'aiDisabled'>, opts: CreateProviderOptions = {}): () => LlmProvider {
  return () => {
    const settings = effectiveAiSettings(config.settings.get());
    return createProvider(
      {
        model: settings.model,
        generationEffort: settings.generationEffort,
        reviewEffort: settings.reviewEffort,
        ...(config.aiDisabled || !settings.aiEnabled ? { forceProvider: 'null' as const } : {}),
      },
      opts,
    );
  };
}
