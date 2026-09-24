/**
 * The real provider: Anthropic's Messages API.
 *
 *  - `structured()` uses `messages.parse` with a strict zod schema, adaptive thinking, an effort setting and a
 *    prompt-cache breakpoint on the last stable system block. The stop reason is checked *before* the output is
 *    read, so a refusal or a truncated answer can never be parsed as a result.
 *  - `agentRun()` is a manual streaming loop over the beta surface, which is where server-side fallbacks live
 *    (`betas: ['server-side-fallback-2026-07-01']`, `fallbacks: 'default'`). Tool inputs are validated with zod by
 *    the shared agent loop before anything touches the disk.
 *
 * Known limitation: `messages.parse` is not on the beta surface, so structured calls do not get a server-side
 * fallback. A refusal there is surfaced to the user as "this step was not done" rather than being retried on another
 * model; the agent runs, which do the expensive work, do get fallbacks.
 */
import Anthropic from '@anthropic-ai/sdk';
import { zodOutputFormat } from '@anthropic-ai/sdk/helpers/zod';
import { z } from 'zod';
import type { LlmUsage } from '@shared/pipeline.js';
import { runAgentLoop, type AgentBlock, type AgentMessage, type AgentStopReason, type AgentTurn } from './agent-loop.js';
import { auditCall, auditCallFrom, hashJson, hashText, storeExchange, type AuditContext, type AuditOptions } from './audit.js';
import { costUsd, emptyLlmUsage } from './budget.js';
import { INVALID_OUTPUT_MESSAGE, MAX_TOKENS_MESSAGE, refusalMessage } from './scripted.js';
import { loadDefaultInjectionPatterns, screenText, type InjectionPatterns } from './screening.js';
import { LlmError, emptyUsageDelta } from './types.js';
import type {
  AgentRunRequest,
  AgentRunResult,
  AgentTool,
  Effort,
  LlmProvider,
  ProviderName,
  StructuredRequest,
  StructuredResult,
  SystemBlock,
  UsageDelta,
} from './types.js';

export const FALLBACK_BETA = 'server-side-fallback-2026-07-01';
export const STRUCTURED_MAX_TOKENS = 32_000;
export const AGENT_MAX_TOKENS = 64_000;
const DEFAULT_TIMEOUT_MS = 20 * 60_000;

export interface AnthropicProviderOptions {
  model?: string;
  apiKey?: string;
  /** Overrides the SDK client (tests). */
  client?: Anthropic;
  timeoutMs?: number;
  maxRetries?: number;
  injectionPatterns?: InjectionPatterns;
  /** Effort for agent runs when the request does not set one. */
  defaultEffort?: Effort;
  /** Where the audit log goes, and whether the redacted prompt/response are stored with it. */
  audit?: AuditOptions;
}

type UsageLike = {
  input_tokens?: number | null;
  output_tokens?: number | null;
  cache_read_input_tokens?: number | null;
  cache_creation_input_tokens?: number | null;
  iterations?: Array<{ type?: string }> | null;
} | null;

export class AnthropicProvider implements LlmProvider {
  readonly name: ProviderName = 'anthropic';
  readonly model: string;
  private readonly client: Anthropic;
  private readonly timeoutMs: number;
  private readonly patterns: InjectionPatterns;
  private readonly defaultEffort: Effort;
  private readonly auditOptions: AuditOptions;

  constructor(opts: AnthropicProviderOptions = {}) {
    this.model = opts.model ?? 'claude-opus-5';
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.patterns = opts.injectionPatterns ?? loadDefaultInjectionPatterns();
    this.defaultEffort = opts.defaultEffort ?? 'high';
    this.auditOptions = opts.audit ?? {};
    this.client =
      opts.client ??
      new Anthropic({
        ...(opts.apiKey ? { apiKey: opts.apiKey } : {}),
        timeout: this.timeoutMs,
        maxRetries: opts.maxRetries ?? 3,
      });
  }

  async structured<T>(req: StructuredRequest<T>): Promise<StructuredResult<T>> {
    const maxTokens = Math.min(req.maxTokens || STRUCTURED_MAX_TOKENS, STRUCTURED_MAX_TOKENS);
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId, req.runId);
    const promptHash = hashJson({ system: req.system, user: req.user });
    try {
      // Streamed (long answers with reasoning need more room than a single request allows) and parsed here rather
      // than by the SDK, whose parse throws on malformed JSON and would lose that call's recorded cost.
      const message = await this.client.messages
        .stream(
          {
            model: this.model,
            max_tokens: maxTokens,
            system: systemParam(req.system),
            messages: [{ role: 'user', content: typeof req.user === 'string' ? req.user : systemParam(req.user) }],
            thinking: { type: 'adaptive' },
            output_config: {
              effort: req.effort,
              format: jsonSchemaFormat(req.schema),
            },
          },
          { ...(req.abort ? { signal: req.abort } : {}), timeout: this.timeoutMs },
        )
        .finalMessage();

      const servedModel = message.model ?? this.model;
      const usage = usageDelta(message.usage as UsageLike, servedModel, this.model, message.stop_reason === 'refusal');

      auditCall(
        context,
        auditCallFrom(usage, {
          stopReason: message.stop_reason ?? 'end_turn',
          ...(message.stop_details?.category ? { stopCategory: message.stop_details.category } : {}),
          promptHash,
          responseHash: hashJson(message.content),
        }),
      );
      storeExchange(
        {
          correlationId: req.correlationId,
          projectId: req.projectId,
          ...(req.runId ? { runId: req.runId } : {}),
          purpose: req.purpose,
          prompt: { system: req.system, user: req.user },
          response: message.content,
        },
        this.auditOptions,
      );

      if (message.stop_reason === 'refusal') {
        const category = message.stop_details?.category ?? undefined;
        return {
          ok: false,
          reason: 'refusal',
          ...(category ? { category } : {}),
          message: refusalMessage(category),
          usage,
        };
      }
      if (message.stop_reason === 'max_tokens') {
        return { ok: false, reason: 'max_tokens', message: MAX_TOKENS_MESSAGE, usage };
      }

      const text = message.content
        .filter((b): b is Anthropic.TextBlock => b.type === 'text')
        .map((b) => b.text)
        .join('');
      const fromText = safeJsonParse(text);
      if (fromText !== undefined) {
        const checked = req.schema.safeParse(fromText);
        if (checked.success) return { ok: true, data: checked.data, usage, servedModel };
      }
      return { ok: false, reason: 'invalid_output', message: INVALID_OUTPUT_MESSAGE, usage };
    } catch (err) {
      const mapped = toLlmError(err);
      const usage = emptyUsageDelta(this.model);
      auditCall(
        context,
        auditCallFrom(usage, { stopReason: 'error', promptHash, responseHash: '', error: mapped.message }),
      );
      return {
        ok: false,
        reason: 'error',
        message: userMessageForError(mapped),
        ...(mapped.kind === 'auth' || mapped.kind === 'billing' ? { accountProblem: true } : {}),
        usage,
      };
    }
  }

  async agentRun(req: AgentRunRequest): Promise<AgentRunResult> {
    const tools = req.tools.map(toolParam);
    const system = systemParam(req.system);
    const effort = req.effort ?? this.defaultEffort;
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId ?? 'unknown', req.runId);

    try {
      return await runAgentLoop(req, {
        provider: this.name,
        model: this.model,
        screen: (text) => screenText(text, this.patterns),
        onTurnAudit: (audit) =>
          auditCall(
            context,
            auditCallFrom(audit.usage, {
              stopReason: audit.stopReason,
              ...(audit.stopCategory ? { stopCategory: audit.stopCategory } : {}),
              promptHash: audit.promptHash ?? '',
              responseHash: audit.responseHash ?? '',
              injectionFlags: audit.injectionFlags,
              pathDenials: audit.pathDenials,
              iteration: audit.iteration,
              durationMs: audit.durationMs,
            }),
          ),
        onStop: (info) => {
          if (!info.budgetStop) return;
          auditCall(context, {
            servedModel: this.model,
            stopReason: 'budget',
            fallbackUsed: false,
            inputTokens: 0,
            outputTokens: 0,
            cacheRead: 0,
            cacheWrite: 0,
            costUsd: 0,
            promptHash: '',
            responseHash: '',
            budgetStop: info.budgetStop,
            iteration: info.iterations,
          });
        },
        runTurn: async ({ messages }) => this.runTurn(messages, system, tools, effort, req.abort),
      });
    } catch (err) {
      const message = userMessageForError(toLlmError(err));
      req.onEvent({ type: 'stop', status: 'error', message });
      return {
        status: 'error',
        ok: false,
        message,
        usage: emptyLlmUsage(this.name, this.model) satisfies LlmUsage,
        iterations: 0,
        servedModels: [],
        pathDenials: 0,
        injectionFlags: 0,
      };
    }
  }

  private auditContext(purpose: AuditContext['purpose'], correlationId: string, projectId: string, runId?: string): AuditContext {
    return {
      provider: this.name,
      requestedModel: this.model,
      purpose,
      correlationId,
      projectId,
      ...(runId ? { runId } : {}),
      options: this.auditOptions,
    };
  }

  private async runTurn(
    messages: AgentMessage[],
    system: Anthropic.TextBlockParam[],
    tools: Anthropic.Beta.BetaTool[],
    effort: Effort,
    abort: AbortSignal,
  ): Promise<AgentTurn> {
    const stream = this.client.beta.messages.stream(
      {
        model: this.model,
        max_tokens: AGENT_MAX_TOKENS,
        system,
        messages: withConversationCache(messages.map(toBetaMessage)),
        tools,
        thinking: { type: 'adaptive' },
        output_config: { effort },
        betas: [FALLBACK_BETA],
        fallbacks: 'default',
      },
      { signal: abort, timeout: this.timeoutMs },
    );

    const onAbort = (): void => stream.abort();
    abort.addEventListener('abort', onAbort, { once: true });
    try {
      const final = await stream.finalMessage();
      const servedModel = final.model ?? this.model;
      const blocks: AgentBlock[] = [];
      for (const block of final.content) {
        if (block.type === 'text') blocks.push({ type: 'text', text: block.text });
        else if (block.type === 'tool_use') blocks.push({ type: 'tool_use', id: block.id, name: block.name, input: block.input });
      }
      const turn: AgentTurn = {
        blocks,
        raw: final.content,
        stopReason: mapStopReason(final.stop_reason),
        usage: usageDelta(final.usage as UsageLike, servedModel, this.model, final.stop_reason === 'refusal'),
        promptHash: hashText(`${hashJson(system)}:${hashJson(messages.map((m) => m.role))}:${messages.length}`),
        responseHash: hashJson(final.content),
      };
      const category = final.stop_details?.category;
      return category ? { ...turn, stopCategory: category } : turn;
    } finally {
      abort.removeEventListener('abort', onAbort);
    }
  }
}

/**
 * The output format without the SDK's own parser: the SDK would throw on an answer that does not match the schema
 * and that call's cost would never be recorded. SecureVibe checks the answer itself (below).
 */
function jsonSchemaFormat(schema: StructuredRequest<unknown>['schema']): { type: 'json_schema'; schema: Record<string, unknown> } {
  const format = zodOutputFormat(schema as Parameters<typeof zodOutputFormat>[0]);
  return { type: format.type, schema: format.schema };
}

function safeJsonParse(text: string): unknown {
  const trimmed = text.trim();
  if (trimmed === '') return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

/** System blocks with a cache breakpoint on every block marked stable (the last one carries the cache prefix). */
export function systemParam(blocks: SystemBlock[]): Anthropic.TextBlockParam[] {
  return blocks
    .filter((b) => b.text.trim() !== '')
    .map((b) => ({
      type: 'text' as const,
      text: b.text,
      ...(b.cache ? { cache_control: { type: 'ephemeral' as const } } : {}),
    }));
}

/** A client tool: zod schema → JSON schema, with eager input streaming so large file writes arrive as they are made. */
export function toolParam(tool: AgentTool): Anthropic.Beta.BetaTool {
  const jsonSchema = zodToJsonSchema(tool.inputSchema);
  return {
    name: tool.name,
    description: tool.description,
    input_schema: jsonSchema as Anthropic.Beta.BetaTool['input_schema'],
    eager_input_streaming: true,
  };
}

function zodToJsonSchema(schema: AgentTool['inputSchema']): Record<string, unknown> {
  // zod 4 ships the converter; `io: 'input'` keeps the schema in the shape the model must produce.
  return z.toJSONSchema(schema, { io: 'input', target: 'draft-2020-12' }) as Record<string, unknown>;
}

function toBetaMessage(message: AgentMessage): Anthropic.Beta.BetaMessageParam {
  if (message.role === 'assistant') {
    const raw = message.raw as Anthropic.Beta.BetaContentBlockParam[] | undefined;
    if (raw && raw.length > 0) return { role: 'assistant', content: raw };
    return {
      role: 'assistant',
      content: message.blocks.flatMap((b): Anthropic.Beta.BetaContentBlockParam[] => {
        if (b.type === 'text') return [{ type: 'text', text: b.text }];
        if (b.type === 'tool_use') return [{ type: 'tool_use', id: b.id, name: b.name, input: b.input as object }];
        return [];
      }),
    };
  }
  return {
    role: 'user',
    content: message.blocks.flatMap((b): Anthropic.Beta.BetaContentBlockParam[] => {
      if (b.type === 'text') return [{ type: 'text', text: b.text }];
      if (b.type === 'tool_result') {
        return [{ type: 'tool_result', tool_use_id: b.toolUseId, content: b.content, is_error: b.isError }];
      }
      return [];
    }),
  };
}

/**
 * Marks the end of the conversation for the prompt cache. Every turn re-sends the whole conversation; with this
 * marker everything up to the previous turn is read from the cache (a tenth of the input price) instead of being
 * paid in full again. It moves forward each turn, so only one marker is used besides the system prompt's.
 */
export function withConversationCache(messages: Anthropic.Beta.BetaMessageParam[]): Anthropic.Beta.BetaMessageParam[] {
  const last = messages.at(-1);
  if (!last || typeof last.content === 'string' || last.content.length === 0) return messages;
  const blocks = [...last.content];
  const end = blocks.length - 1;
  const block = blocks[end]!;
  if (block.type !== 'text' && block.type !== 'tool_result') return messages;
  blocks[end] = { ...block, cache_control: { type: 'ephemeral' } };
  return [...messages.slice(0, -1), { ...last, content: blocks }];
}

export function mapStopReason(reason: string | null | undefined): AgentStopReason {
  switch (reason) {
    case 'end_turn':
    case 'tool_use':
    case 'max_tokens':
    case 'refusal':
    case 'pause_turn':
      return reason;
    default:
      return 'other';
  }
}

export function usageDelta(usage: UsageLike, servedModel: string, requestedModel: string, refused: boolean): UsageDelta {
  const counts = {
    inputTokens: usage?.input_tokens ?? 0,
    outputTokens: usage?.output_tokens ?? 0,
    cacheReadTokens: usage?.cache_read_input_tokens ?? 0,
    cacheWriteTokens: usage?.cache_creation_input_tokens ?? 0,
  };
  const fallbackUsed =
    servedModel !== requestedModel || (usage?.iterations ?? []).some((i) => i?.type === 'fallback_message');
  return { ...counts, costUsd: costUsd(servedModel, counts), servedModel, fallbackUsed, refused };
}

/** Maps SDK errors onto the kinds the pipeline reacts to. The API key is never part of a message. */
export function toLlmError(err: unknown): LlmError {
  if (err instanceof LlmError) return err;
  if (err instanceof Anthropic.AuthenticationError) return new LlmError('auth', 'the API key was not accepted');
  if (err instanceof Anthropic.APIError && /credit balance/i.test(err.message)) return new LlmError('billing', 'the Anthropic account has no credit left');
  if (err instanceof Anthropic.RateLimitError) return new LlmError('rate-limit', 'the API rate limit was reached');
  if (err instanceof Anthropic.BadRequestError) return new LlmError('bad-request', err.message);
  if (err instanceof Anthropic.APIConnectionError) return new LlmError('network', 'the connection to the API failed');
  if (err instanceof Anthropic.APIError) return new LlmError('api', err.message);
  const message = err instanceof Error ? err.message : String(err);
  if (/abort/i.test(message)) return new LlmError('aborted', message);
  return new LlmError('unknown', message);
}

/** Plain-language message for the person using SecureVibe — never a stack trace, never a credential. */
export function userMessageForError(err: LlmError): string {
  switch (err.kind) {
    case 'auth':
      return 'The Anthropic API key was not accepted. Check the key in your .env file, then try again.';
    case 'billing':
      return 'Your Anthropic account has run out of credit. Add credit in the Anthropic Console (Plans & Billing), then try again.';
    case 'rate-limit':
      return 'Anthropic is rate-limiting this key right now. Wait a few minutes and try again.';
    case 'network':
      return 'SecureVibe could not reach the Anthropic API. Check your internet connection and try again.';
    case 'aborted':
      return 'The step was canceled.';
    case 'bad-request':
      return `The AI rejected the request: ${err.message}`;
    default:
      return `The AI step could not be completed: ${err.message}`;
  }
}
