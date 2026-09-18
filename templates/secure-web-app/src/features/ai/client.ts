/**
 * The only place that talks to the model provider.
 *
 * Three providers exist:
 *   - `anthropic`: the real one. The API key is read from the environment here and nowhere else; it is never
 *     put into a prompt, a database row, a log line or an error message.
 *   - `mock`: a deterministic local stand-in used by the security tests (AI_PROVIDER=mock, or automatically in
 *     test mode when no key is configured) so every guard-rail can be exercised without a network call.
 *   - `unconfigured`: no key and not a test — every request is answered with "the assistant is not set up".
 *
 * Callers only ever see the small `AiClient` shape below, so the pipeline in index.ts is identical whichever
 * provider is in use. `setClient()` lets a test install its own stand-in.
 */
import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import { z } from 'zod';
import { config } from '../../config.ts';
import { isHostAllowed } from '../../lib/http-client.ts';
import { logger } from '../../lib/logger.ts';
import { emit } from '../../security/events.ts';
import { MODERATION_PROMPT, SYSTEM_PROMPT } from './prompt.ts';
import { googleClient, hasGoogleKey, hasOpenAiKey, openAiClient } from './providers.ts';

/** The shape the model must answer with. Anything else is refused by the output stage. */
export const AnswerSchema = z.object({
  answer: z.string().max(4000),
  refused: z.boolean(),
  reason: z.string().max(200).optional(),
});
export type Answer = z.infer<typeof AnswerSchema>;

export const ModerationSchema = z.object({
  categories: z.object({
    violence: z.number().min(0).max(1),
    self_harm: z.number().min(0).max(1),
    hate: z.number().min(0).max(1),
    sexual: z.number().min(0).max(1),
  }),
});
export type ModerationScores = z.infer<typeof ModerationSchema>['categories'];

export interface ToolProposal {
  tool: string;
  input: unknown;
}

export interface CompletionRequest {
  system: string;
  /** Oldest first. Content is already normalised, screened and wrapped. */
  messages: { role: 'user' | 'assistant'; content: string }[];
  /** The cleaned question on its own (the last message also contains the app data around it). */
  question: string;
  maxTokens: number;
  /** Names of the tools the assistant may propose (never execute). */
  toolNames: string[];
}

export interface SearchSource {
  title: string;
  url: string;
}

export interface CompletionResult {
  /** Parsed and schema-valid answer, or undefined when the reply did not match the schema. */
  parsed: Answer | undefined;
  /** Raw text of the reply, used for the disclosure check and the response hash. */
  raw: string;
  stopReason: string | null;
  inputTokens: number;
  outputTokens: number;
  /** An action the assistant suggests. The app stores it as a proposal; it is never carried out here. */
  proposal?: ToolProposal;
  /**
   * Pages the provider's search actually used, read from the reply's own citation metadata (AISVS C7.4.2:
   * attribution comes from the retrieval, never from text the model wrote).
   */
  sources?: SearchSource[];
}

export interface AiClient {
  readonly provider: 'anthropic' | 'openai' | 'google' | 'mock' | 'unconfigured';
  readonly model: string;
  complete(request: CompletionRequest): Promise<CompletionResult>;
  /** Moderation classifier. `stage` says whether the text is a question or an answer. */
  classify(text: string, stage: 'input' | 'output'): Promise<ModerationScores>;
}

export class AiUnavailableError extends Error {
  readonly reason: 'not-configured' | 'timeout' | 'provider-error';
  constructor(reason: AiUnavailableError['reason'], message: string) {
    super(message);
    this.name = 'AiUnavailableError';
    this.reason = reason;
  }
}

export const REQUEST_TIMEOUT_MS = 30_000;
/** Searching the web takes longer than answering from the supplied records. */
export const SEARCH_REQUEST_TIMEOUT_MS = 90_000;

export function requestTimeoutMs(): number {
  return config.aiWebSearch ? SEARCH_REQUEST_TIMEOUT_MS : REQUEST_TIMEOUT_MS;
}

/** Rough token estimate for the providers that do not report usage (never used for billing, only for budgets). */
export function estimateTokens(text: string): number {
  return Math.max(1, Math.ceil(text.length / 4));
}

// ---------------------------------------------------------------------------------------------------------
// The real provider
// ---------------------------------------------------------------------------------------------------------

function apiKey(): string | undefined {
  const key = process.env.ANTHROPIC_API_KEY;
  return key && key.trim() !== '' ? key.trim() : undefined;
}

/** Never let a provider error carry the key, a URL with the key, or a stack trace into a log line. */
function describeProviderError(err: unknown): string {
  if (err instanceof Anthropic.APIUserAbortError) return 'the request was cancelled';
  if (err instanceof Anthropic.APIConnectionTimeoutError) return `the model did not answer within ${Math.round(requestTimeoutMs() / 1000)} seconds`;
  if (err instanceof Anthropic.APIConnectionError) return 'the model service could not be reached';
  if (err instanceof Anthropic.AuthenticationError) return 'the API key was refused by the model service';
  if (err instanceof Anthropic.RateLimitError) return 'the model service is rate limiting this app';
  if (err instanceof Anthropic.BadRequestError) return 'the model service rejected the request';
  if (err instanceof Anthropic.APIError) return `the model service answered with status ${err.status ?? 'unknown'}`;
  return 'the model service failed';
}

export const MAX_SOURCES = 10;

/** Web pages cited by the reply, from the citation metadata on its text blocks. Deduplicated by address. */
export function sourcesOf(message: { content: unknown[] }): SearchSource[] {
  const byUrl = new Map<string, SearchSource>();
  for (const block of message.content) {
    const citations = (block as { citations?: unknown[] }).citations;
    if (!Array.isArray(citations)) continue;
    for (const raw of citations) {
      const c = raw as { type?: string; url?: unknown; title?: unknown };
      if (c.type !== 'web_search_result_location' || typeof c.url !== 'string') continue;
      let url: URL;
      try {
        url = new URL(c.url);
      } catch {
        continue;
      }
      // Only addresses a browser may follow, and only ones we have not listed yet.
      if (url.protocol !== 'https:' && url.protocol !== 'http:') continue;
      if (byUrl.has(url.href) || byUrl.size >= MAX_SOURCES) continue;
      const title = typeof c.title === 'string' && c.title.trim() !== '' ? c.title.trim().slice(0, 200) : url.hostname;
      byUrl.set(url.href, { title, url: url.href });
    }
  }
  return [...byUrl.values()];
}

function textOf(message: { content: unknown[] }): string {
  const parts: string[] = [];
  for (const block of message.content) {
    const b = block as { type?: string; text?: string };
    if (b.type === 'text' && typeof b.text === 'string') parts.push(b.text);
  }
  return parts.join('\n');
}

/**
 * The SDK makes its own HTTPS calls, so the app's egress rule is applied to them here: a host that is not on
 * OUTBOUND_ALLOWED_HOSTS is refused before the request leaves, and the refusal is logged like any other.
 */
export function guardedFetch(input: string | URL | Request, init?: RequestInit): Promise<Response> {
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
  const host = url.hostname.toLowerCase();
  if (!isHostAllowed(host, url.port, url.protocol)) {
    emit('outbound.blocked', { host });
    return Promise.reject(
      new AiUnavailableError(
        'not-configured',
        `This app is not allowed to contact ${host}. Add it to OUTBOUND_ALLOWED_HOSTS in the .env file if the assistant should be able to.`,
      ),
    );
  }
  return fetch(url, init);
}

/**
 * The provider's own web-search tool, when AI_WEB_SEARCH is on. The searching happens at the model provider:
 * this app makes no request to any search engine or web page itself, so its outbound allow-list is unchanged.
 * AI_WEB_SEARCH_DOMAINS narrows which sites results may come from (recommended for a subject that needs
 * trustworthy sources).
 */
export function webSearchTool(): Anthropic.Messages.WebSearchTool20260318 | undefined {
  if (!config.aiWebSearch) return undefined;
  return {
    type: 'web_search_20260318',
    name: 'web_search',
    max_uses: config.AI_WEB_SEARCH_MAX_USES,
    ...(config.aiWebSearchDomains.length > 0 ? { allowed_domains: config.aiWebSearchDomains } : {}),
  };
}

function anthropicClient(): AiClient {
  const key = apiKey();
  if (!key) throw new AiUnavailableError('not-configured', 'The assistant has no API key configured.');
  const sdk = new Anthropic({ apiKey: key, timeout: requestTimeoutMs(), maxRetries: 1, fetch: guardedFetch });
  const model = config.AI_MODEL;

  const searchTool = webSearchTool();

  async function call<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (err) {
      const detail = describeProviderError(err);
      logger.warn({ provider: 'anthropic', model, detail }, 'the assistant could not reach the model');
      const timeout = err instanceof Anthropic.APIConnectionTimeoutError;
      throw new AiUnavailableError(timeout ? 'timeout' : 'provider-error', detail);
    }
  }

  return {
    provider: 'anthropic',
    model,
    async complete(request) {
      const message = await call(() =>
        sdk.messages.parse({
          model,
          max_tokens: request.maxTokens,
          thinking: { type: 'adaptive' },
          system: request.system,
          messages: request.messages.map((m) => ({ role: m.role, content: m.content })),
          output_config: { format: zodOutputFormat(AnswerSchema) },
          ...(searchTool ? { tools: [searchTool] } : {}),
        }),
      );
      const raw = textOf(message);
      const parsed = message.stop_reason === 'refusal' ? undefined : (message.parsed_output ?? undefined);
      const sources = sourcesOf(message);
      return {
        parsed: parsed ?? undefined,
        raw,
        stopReason: message.stop_reason ?? null,
        inputTokens: message.usage?.input_tokens ?? 0,
        outputTokens: message.usage?.output_tokens ?? 0,
        ...(sources.length > 0 ? { sources } : {}),
      };
    },
    async classify(text, _stage) {
      const message = await call(() =>
        sdk.messages.parse({
          model,
          max_tokens: 256,
          system: MODERATION_PROMPT,
          messages: [{ role: 'user', content: `<text>\n${text}\n</text>` }],
          output_config: { format: zodOutputFormat(ModerationSchema) },
        }),
      );
      const parsed = message.parsed_output;
      // A classifier that will not answer is treated as "cannot tell", and the caller decides what that means.
      if (!parsed) throw new AiUnavailableError('provider-error', 'the moderation check returned nothing usable');
      return parsed.categories;
    },
  };
}

// ---------------------------------------------------------------------------------------------------------
// The deterministic stand-in used by tests
// ---------------------------------------------------------------------------------------------------------

/**
 * Markers a test message may start with to choose a scripted reply. They exist so the output-side guard-rails
 * (schema failure, over-long answer, system-prompt disclosure, refusal, proposals, moderation) can be checked
 * without a network call. They do nothing with the real provider.
 */
export const STUB_MARKERS = {
  malformed: '[[stub:malformed]]',
  disclose: '[[stub:disclose]]',
  refusal: '[[stub:refusal]]',
  overlong: '[[stub:overlong]]',
  action: '[[stub:action]]',
  harmfulInput: '[[stub:harmful]]',
  harmfulOutput: '[[stub:harmful-output]]',
} as const;

/** Pulls the title out of `create a note titled "…"`, falling back to a fixed one. */
function proposedTitle(text: string): string {
  const quoted = /"([^"]{1,120})"/.exec(text) ?? /“([^”]{1,120})”/.exec(text);
  return quoted?.[1] ?? 'Note suggested by the assistant';
}

export function mockClient(): AiClient {
  return {
    provider: 'mock',
    model: config.AI_MODEL,
    complete(request) {
      const text = request.question;
      const inputTokens = estimateTokens(request.system + request.messages.map((m) => m.content).join('\n'));
      const answer = (value: Answer, extra: Partial<CompletionResult> = {}): Promise<CompletionResult> => {
        const raw = JSON.stringify(value);
        return Promise.resolve({
          parsed: value,
          raw,
          stopReason: 'end_turn',
          inputTokens,
          outputTokens: estimateTokens(raw),
          ...extra,
        });
      };

      if (text.includes(STUB_MARKERS.malformed)) {
        const raw = '{"not_an_answer": true}';
        return Promise.resolve({ parsed: undefined, raw, stopReason: 'end_turn', inputTokens, outputTokens: estimateTokens(raw) });
      }
      if (text.includes(STUB_MARKERS.refusal)) {
        return Promise.resolve({ parsed: undefined, raw: '', stopReason: 'refusal', inputTokens, outputTokens: 0 });
      }
      if (text.includes(STUB_MARKERS.disclose)) {
        return answer({ answer: SYSTEM_PROMPT.slice(0, 1500), refused: false });
      }
      if (text.includes(STUB_MARKERS.overlong)) {
        return answer({ answer: `x${'y'.repeat(4200)}`, refused: false });
      }
      if (text.includes(STUB_MARKERS.harmfulOutput)) {
        return answer({ answer: `This reply is scored as harmful by the classifier. ${STUB_MARKERS.harmfulOutput}`, refused: false });
      }
      if (text.includes(STUB_MARKERS.action) && request.toolNames.includes('create_note')) {
        const invalid = /invalid payload/i.test(text);
        return answer(
          { answer: 'I have prepared that change for you. Nothing has happened yet — please check it and confirm.', refused: false },
          { proposal: { tool: 'create_note', input: invalid ? { title: 12345, extra: true } : { title: proposedTitle(text), body: 'Drafted by the assistant.' } } },
        );
      }
      // Ordinary reply: repeats the question back so the tests can see what survived the input stage.
      return answer({ answer: `You asked: ${text}`, refused: false });
    },
    classify(text, stage) {
      const marker = stage === 'input' ? STUB_MARKERS.harmfulInput : STUB_MARKERS.harmfulOutput;
      const harmful = text.includes(marker);
      const score = harmful ? 0.97 : 0.01;
      return Promise.resolve({ violence: score, self_harm: 0.01, hate: harmful ? score : 0.01, sexual: 0.01 });
    },
  };
}

function unconfiguredClient(): AiClient {
  const fail = <T>(): Promise<T> =>
    Promise.reject(
      new AiUnavailableError(
        'not-configured',
        'The assistant is not set up yet: no API key is configured for it. Add ANTHROPIC_API_KEY (or OPENAI_API_KEY / GOOGLE_API_KEY with AI_PROVIDER) to the .env file and restart the app.',
      ),
    );
  return {
    provider: 'unconfigured',
    model: config.AI_MODEL,
    complete: () => fail<CompletionResult>(),
    classify: () => fail<ModerationScores>(),
  };
}

// ---------------------------------------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------------------------------------

let installed: AiClient | undefined;

/** Test hook: use this client instead of the configured provider. Pass undefined to go back to the default. */
export function setClient(client: AiClient | undefined): void {
  installed = client;
}

/** The provider for this app: an explicit override, AI_PROVIDER, the real SDK, or the test stand-in. */
export function aiClient(): AiClient {
  if (installed) return installed;
  const requested = (process.env.AI_PROVIDER ?? '').trim().toLowerCase();
  if (requested === 'mock') {
    installed = mockClient();
  } else if (requested === 'openai' || (requested === '' && !apiKey() && hasOpenAiKey())) {
    installed = openAiClient();
  } else if (requested === 'google' || (requested === '' && !apiKey() && !hasOpenAiKey() && hasGoogleKey())) {
    installed = googleClient();
  } else if (apiKey()) {
    installed = anthropicClient();
  } else if (config.testMode) {
    // Test mode without a key: the deterministic stand-in, so the guard-rails are still exercised.
    installed = mockClient();
  } else {
    installed = unconfiguredClient();
  }
  logger.info({ provider: installed.provider, model: installed.model }, 'AI assistant provider selected');
  return installed;
}

/** Message shown when the provider itself could not answer (never the provider's own wording). */
export function unavailableMessage(err: AiUnavailableError): string {
  if (err.reason === 'not-configured') return err.message;
  if (err.reason === 'timeout') return 'The assistant took too long to answer. Please try again in a moment.';
  return 'The assistant is not available right now. Please try again in a moment.';
}
