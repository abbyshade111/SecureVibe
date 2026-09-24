/**
 * Chooses the provider for this installation (CONTRACTS §9.1):
 *   scripted   — a scenario folder is configured (tests, demos);
 *   anthropic  — a credential is present in the environment;
 *   null       — preview mode: everything that needs AI is skipped and labeled.
 *
 * An explicitly configured scenario folder wins over a credential that merely happens to be in the environment, so a
 * test run on a developer's machine can never reach the real API by accident. `forceProvider` overrides both.
 *
 * The credential itself is never read into SecureVibe's own state, never logged and never written to disk;
 * `hasCredentials()` only asks whether the variable is set.
 */
import { AnthropicProvider, type AnthropicProviderOptions } from './anthropic.js';
import { GoogleProvider, type GoogleProviderOptions } from './google.js';
import { OpenAiProvider, type OpenAiProviderOptions } from './openai.js';
import { NullProvider, PREVIEW_EXPLANATION } from './null.js';
import { ScriptedProvider, type ScriptedOptions } from './scripted.js';
import type { Effort, LlmProvider, ProviderName } from './types.js';

/** Environment variables the Anthropic SDK accepts as a credential. */
export const CREDENTIAL_ENV_VARS = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN'] as const;

/** True when a credential is available. Only the presence of the variable is checked — never its value. */
export function hasCredentials(env: NodeJS.ProcessEnv = process.env): boolean {
  return CREDENTIAL_ENV_VARS.some((name) => {
    const value = env[name];
    return typeof value === 'string' && value.trim() !== '';
  });
}

export type AiService = 'anthropic' | 'openai' | 'google';
const SERVICE_ENV: Record<AiService, readonly string[]> = { anthropic: CREDENTIAL_ENV_VARS, openai: ['OPENAI_API_KEY'], google: ['GOOGLE_API_KEY'] };

/** True when the named service has a credential in the environment (presence only, never the value). */
export function hasCredentialsFor(service: AiService, env: NodeJS.ProcessEnv = process.env): boolean {
  return SERVICE_ENV[service].some((name) => {
    const value = env[name];
    return typeof value === 'string' && value.trim() !== '';
  });
}

/** The settings fields the factory looks at (a subset of SecureVibe's settings plus test-only fields). */
export interface ProviderSettings {
  model?: string;
  /** The service builds use (default anthropic); it needs a key, otherwise preview mode. */
  aiService?: AiService;
  generationEffort?: Effort;
  reviewEffort?: Effort;
  /** Folder of scripted scenario files; when set, the scripted provider is used. */
  scriptedScenarioDir?: string;
  /** Overrides the automatic choice (used by `npm run smoke:api` and by tests). */
  forceProvider?: ProviderName;
}

export interface CreateProviderOptions {
  env?: NodeJS.ProcessEnv;
  /** Extra options handed to the chosen provider. */
  anthropic?: AnthropicProviderOptions;
  openai?: OpenAiProviderOptions;
  google?: GoogleProviderOptions;
  scripted?: Omit<ScriptedOptions, 'dir'> & { dir?: string };
}

export interface ProviderStatus {
  provider: ProviderName;
  model: string;
  configured: boolean;
  previewMode: boolean;
  /** Plain-language explanation shown on the home page and in the reports. */
  message: string;
}

const DEFAULT_MODEL = 'claude-opus-5';

export function createProvider(settings: ProviderSettings = {}, opts: CreateProviderOptions = {}): LlmProvider {
  const env = opts.env ?? process.env;
  const model = settings.model ?? DEFAULT_MODEL;
  const forced = settings.forceProvider;

  if (forced === 'null') return new NullProvider(model);

  const scriptedDir = opts.scripted?.dir ?? settings.scriptedScenarioDir;
  if (forced === 'scripted' || (!forced && scriptedDir)) {
    if (!scriptedDir) throw new Error('the scripted provider needs settings.scriptedScenarioDir');
    return new ScriptedProvider({ ...opts.scripted, dir: scriptedDir, model: opts.scripted?.model ?? model });
  }

  const service: AiService = forced === 'openai' || forced === 'google' || forced === 'anthropic' ? forced : (settings.aiService ?? 'anthropic');
  const effort = settings.generationEffort ? { defaultEffort: settings.generationEffort } : {};
  if (service === 'openai' && (forced === 'openai' || hasCredentialsFor('openai', env))) {
    return new OpenAiProvider({ model, ...effort, ...opts.openai });
  }
  if (service === 'google' && (forced === 'google' || hasCredentialsFor('google', env))) {
    return new GoogleProvider({ model, ...effort, ...opts.google });
  }
  if (service === 'anthropic' && (forced === 'anthropic' || hasCredentials(env))) {
    return new AnthropicProvider({ model, ...effort, ...opts.anthropic });
  }

  return new NullProvider(model);
}

/** What the status endpoint and the reports say about the AI configuration. */
export function providerStatus(provider: LlmProvider): ProviderStatus {
  switch (provider.name) {
    case 'anthropic':
      return {
        provider: 'anthropic',
        model: provider.model,
        configured: true,
        previewMode: false,
        message: `Claude is connected and will use the ${provider.model} model.`,
      };
    case 'openai':
      return { provider: 'openai', model: provider.model, configured: true, previewMode: false, message: `OpenAI is connected and will use the ${provider.model} model.` };
    case 'google':
      return { provider: 'google', model: provider.model, configured: true, previewMode: false, message: `Google Gemini is connected and will use the ${provider.model} model.` };
    case 'scripted':
      return {
        provider: 'scripted',
        model: provider.model,
        configured: true,
        previewMode: false,
        message: 'SecureVibe is replaying recorded AI answers. This mode is for testing only.',
      };
    default:
      return {
        provider: 'null',
        model: provider.model,
        configured: false,
        previewMode: true,
        message: PREVIEW_EXPLANATION,
      };
  }
}
