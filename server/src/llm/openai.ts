/**
 * OpenAI provider (Responses API over plain HTTPS; no SDK).
 *
 *  - `structured()` asks for a strict JSON-schema answer, sets the reasoning effort, and checks the answer's status
 *    and refusal before parsing it with zod.
 *  - `agentRun()` supplies one model turn to the shared agent loop: function tools with strict input schemas, the
 *    conversation replayed statelessly (`store: false`, encrypted reasoning items carried along), tool calls mapped
 *    to the loop's blocks. The loop validates tool inputs and fences file paths as for every provider.
 *
 * Prompt caching is automatic at OpenAI (cached input tokens are reported and priced at the cache-read rate); the
 * `cache` markers on system blocks are simply concatenated in order.
 */
import { z } from 'zod';
import type { LlmUsage } from '@shared/pipeline.js';
import { runAgentLoop, type AgentBlock, type AgentMessage, type AgentStopReason, type AgentTurn } from './agent-loop.js';
import { auditCall, auditCallFrom, hashJson, hashText, storeExchange, type AuditContext, type AuditOptions } from './audit.js';
import { costUsd, emptyLlmUsage } from './budget.js';
import { postJson, strictJsonSchema, userMessageFor, type FetchLike } from './rest.js';
import { INVALID_OUTPUT_MESSAGE, MAX_TOKENS_MESSAGE, refusalMessage } from './scripted.js';
import { loadDefaultInjectionPatterns, screenText, type InjectionPatterns } from './screening.js';
import { LlmError, emptyUsageDelta } from './types.js';
import type { AgentRunRequest, AgentRunResult, AgentTool, Effort, LlmProvider, ProviderName, StructuredRequest, StructuredResult, SystemBlock, UsageDelta } from './types.js';

export const DEFAULT_OPENAI_MODEL = 'gpt-5';
export const OPENAI_STRUCTURED_MAX_TOKENS = 32_000;
export const OPENAI_AGENT_MAX_TOKENS = 64_000;
const DEFAULT_TIMEOUT_MS = 20 * 60_000;
const SERVICE = 'OpenAI';

export interface OpenAiProviderOptions {
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  injectionPatterns?: InjectionPatterns;
  defaultEffort?: Effort;
  audit?: AuditOptions;
}

interface ResponsesOutputItem {
  type: string;
  id?: string;
  status?: string;
  role?: string;
  content?: { type: string; text?: string; refusal?: string }[];
  call_id?: string;
  name?: string;
  arguments?: string;
  encrypted_content?: string;
  summary?: unknown[];
}

interface ResponsesReply {
  id?: string;
  model?: string;
  status?: string;
  incomplete_details?: { reason?: string } | null;
  output?: ResponsesOutputItem[];
  usage?: { input_tokens?: number; output_tokens?: number; input_tokens_details?: { cached_tokens?: number } } | null;
}

/** OpenAI knows three effort levels; SecureVibe's higher ones map to the highest. */
export function openAiEffort(effort: Effort): 'low' | 'medium' | 'high' {
  return effort === 'low' ? 'low' : effort === 'medium' ? 'medium' : 'high';
}

export function systemText(blocks: SystemBlock[]): string {
  return blocks
    .filter((b) => b.text.trim() !== '')
    .map((b) => b.text)
    .join('\n\n');
}

export class OpenAiProvider implements LlmProvider {
  readonly name: ProviderName = 'openai';
  readonly model: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike | undefined;
  private readonly timeoutMs: number;
  private readonly patterns: InjectionPatterns;
  private readonly defaultEffort: Effort;
  private readonly auditOptions: AuditOptions;

  constructor(opts: OpenAiProviderOptions = {}) {
    this.model = opts.model ?? DEFAULT_OPENAI_MODEL;
    this.apiKey = opts.apiKey ?? process.env['OPENAI_API_KEY'] ?? '';
    this.baseUrl = (opts.baseUrl ?? 'https://api.openai.com/v1').replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.patterns = opts.injectionPatterns ?? loadDefaultInjectionPatterns();
    this.defaultEffort = opts.defaultEffort ?? 'high';
    this.auditOptions = opts.audit ?? {};
  }

  private headers(): Record<string, string> {
    return { authorization: `Bearer ${this.apiKey}` };
  }

  private post(body: unknown, abort?: AbortSignal): Promise<ResponsesReply> {
    return postJson(`${this.baseUrl}/responses`, this.headers(), body, {
      ...(this.fetchImpl ? { fetchImpl: this.fetchImpl } : {}),
      timeoutMs: this.timeoutMs,
      ...(abort ? { abort } : {}),
      service: SERVICE,
    }) as Promise<ResponsesReply>;
  }

  async structured<T>(req: StructuredRequest<T>): Promise<StructuredResult<T>> {
    const maxTokens = Math.min(req.maxTokens || OPENAI_STRUCTURED_MAX_TOKENS, OPENAI_STRUCTURED_MAX_TOKENS);
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId, req.runId);
    const promptHash = hashJson({ system: req.system, user: req.user });
    const userText = typeof req.user === 'string' ? req.user : systemText(req.user);
    try {
      const reply = await this.post(
        {
          model: this.model,
          instructions: systemText(req.system),
          input: [{ role: 'user', content: [{ type: 'input_text', text: userText }] }],
          text: { format: { type: 'json_schema', name: 'result', schema: strictJsonSchema(z.toJSONSchema(req.schema as z.ZodType, { target: 'draft-2020-12' }) as Record<string, unknown>), strict: true } },
          reasoning: { effort: openAiEffort(req.effort) },
          max_output_tokens: maxTokens,
          store: false,
        },
        req.abort,
      );
      const servedModel = reply.model ?? this.model;
      const refusal = refusalOf(reply);
      const usage = usageOf(reply, servedModel, this.model, refusal !== undefined);
      const truncated = reply.status === 'incomplete' && reply.incomplete_details?.reason === 'max_output_tokens';
      auditCall(context, auditCallFrom(usage, { stopReason: refusal !== undefined ? 'refusal' : truncated ? 'max_tokens' : 'end_turn', promptHash, responseHash: hashJson(reply.output ?? []) }));
      storeExchange({ correlationId: req.correlationId, projectId: req.projectId, ...(req.runId ? { runId: req.runId } : {}), purpose: req.purpose, prompt: { system: req.system, user: req.user }, response: reply.output ?? [] }, this.auditOptions);

      if (refusal !== undefined) return { ok: false, reason: 'refusal', message: refusalMessage(undefined), usage };
      if (truncated) return { ok: false, reason: 'max_tokens', message: MAX_TOKENS_MESSAGE, usage };
      const parsed = safeJsonParse(outputText(reply));
      if (parsed !== undefined) {
        const checked = req.schema.safeParse(parsed);
        if (checked.success) return { ok: true, data: checked.data, usage, servedModel };
      }
      return { ok: false, reason: 'invalid_output', message: INVALID_OUTPUT_MESSAGE, usage };
    } catch (err) {
      const mapped = err instanceof LlmError ? err : new LlmError('unknown', err instanceof Error ? err.message : String(err));
      const usage = emptyUsageDelta(this.model);
      auditCall(context, auditCallFrom(usage, { stopReason: 'error', promptHash, responseHash: '', error: mapped.message }));
      return { ok: false, reason: 'error', message: userMessageFor(SERVICE, mapped), ...(mapped.kind === 'auth' || mapped.kind === 'billing' ? { accountProblem: true } : {}), usage };
    }
  }

  async agentRun(req: AgentRunRequest): Promise<AgentRunResult> {
    const tools = req.tools.map(toolParam);
    const instructions = systemText(req.system);
    const effort = req.effort ?? this.defaultEffort;
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId ?? 'unknown', req.runId);
    try {
      return await runAgentLoop(req, {
        provider: this.name,
        model: this.model,
        screen: (text) => screenText(text, this.patterns),
        onTurnAudit: (audit) =>
          auditCall(context, auditCallFrom(audit.usage, { stopReason: audit.stopReason, promptHash: audit.promptHash ?? '', responseHash: audit.responseHash ?? '', injectionFlags: audit.injectionFlags, pathDenials: audit.pathDenials, iteration: audit.iteration, durationMs: audit.durationMs })),
        onStop: (info) => {
          if (!info.budgetStop) return;
          auditCall(context, { servedModel: this.model, stopReason: 'budget', fallbackUsed: false, inputTokens: 0, outputTokens: 0, cacheRead: 0, cacheWrite: 0, costUsd: 0, promptHash: '', responseHash: '', budgetStop: info.budgetStop, iteration: info.iterations });
        },
        runTurn: async ({ messages }) => this.runTurn(messages, instructions, tools, effort, req.abort),
      });
    } catch (err) {
      const mapped = err instanceof LlmError ? err : new LlmError('unknown', err instanceof Error ? err.message : String(err));
      const message = userMessageFor(SERVICE, mapped);
      req.onEvent({ type: 'stop', status: 'error', message });
      return { status: 'error', ok: false, message, usage: emptyLlmUsage(this.name, this.model) satisfies LlmUsage, iterations: 0, servedModels: [], pathDenials: 0, injectionFlags: 0 };
    }
  }

  private auditContext(purpose: AuditContext['purpose'], correlationId: string, projectId: string, runId?: string): AuditContext {
    return { provider: this.name, requestedModel: this.model, purpose, correlationId, projectId, ...(runId ? { runId } : {}), options: this.auditOptions };
  }

  private async runTurn(messages: AgentMessage[], instructions: string, tools: unknown[], effort: Effort, abort: AbortSignal): Promise<AgentTurn> {
    const reply = await this.post(
      {
        model: this.model,
        instructions,
        input: messages.flatMap(toInputItems),
        tools,
        reasoning: { effort: openAiEffort(effort) },
        max_output_tokens: OPENAI_AGENT_MAX_TOKENS,
        store: false,
        include: ['reasoning.encrypted_content'],
      },
      abort,
    );
    const servedModel = reply.model ?? this.model;
    const output = reply.output ?? [];
    const blocks: AgentBlock[] = [];
    let refused = false;
    for (const item of output) {
      if (item.type === 'message') {
        for (const c of item.content ?? []) {
          if (c.type === 'output_text' && c.text) blocks.push({ type: 'text', text: c.text });
          if (c.type === 'refusal') refused = true;
        }
      } else if (item.type === 'function_call' && item.name) {
        blocks.push({ type: 'tool_use', id: item.call_id ?? item.id ?? `call_${blocks.length}`, name: item.name, input: safeJsonParse(item.arguments ?? '') ?? {} });
      }
    }
    const truncated = reply.status === 'incomplete' && reply.incomplete_details?.reason === 'max_output_tokens';
    const stopReason: AgentStopReason = refused ? 'refusal' : truncated ? 'max_tokens' : blocks.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn';
    return {
      blocks,
      raw: output,
      stopReason,
      usage: usageOf(reply, servedModel, this.model, refused),
      promptHash: hashText(`${hashText(instructions)}:${hashJson(messages.map((m) => m.role))}:${messages.length}`),
      responseHash: hashJson(output),
    };
  }
}

/** A client tool for the Responses API: strict input schema, so the model cannot invent fields. */
export function toolParam(tool: AgentTool): unknown {
  return { type: 'function', name: tool.name, description: tool.description, parameters: strictJsonSchema(z.toJSONSchema(tool.inputSchema, { io: 'input', target: 'draft-2020-12' }) as Record<string, unknown>), strict: true };
}

/** The conversation as Responses API input items: assistant output items replayed as they came back. */
export function toInputItems(message: AgentMessage): unknown[] {
  if (message.role === 'assistant') {
    const raw = message.raw as ResponsesOutputItem[] | undefined;
    if (raw && raw.length > 0) return raw;
    return message.blocks.flatMap((b): unknown[] => {
      if (b.type === 'text') return [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: b.text }] }];
      if (b.type === 'tool_use') return [{ type: 'function_call', call_id: b.id, name: b.name, arguments: JSON.stringify(b.input ?? {}) }];
      return [];
    });
  }
  return message.blocks.flatMap((b): unknown[] => {
    if (b.type === 'text') return [{ role: 'user', content: [{ type: 'input_text', text: b.text }] }];
    if (b.type === 'tool_result') return [{ type: 'function_call_output', call_id: b.toolUseId, output: b.isError ? `ERROR: ${b.content}` : b.content }];
    return [];
  });
}

function outputText(reply: ResponsesReply): string {
  return (reply.output ?? [])
    .filter((item) => item.type === 'message')
    .flatMap((item) => item.content ?? [])
    .filter((c) => c.type === 'output_text')
    .map((c) => c.text ?? '')
    .join('');
}

function refusalOf(reply: ResponsesReply): string | undefined {
  for (const item of reply.output ?? []) {
    if (item.type !== 'message') continue;
    const r = (item.content ?? []).find((c) => c.type === 'refusal');
    if (r) return r.refusal ?? '';
  }
  return undefined;
}

export function usageOf(reply: ResponsesReply, servedModel: string, requestedModel: string, refused: boolean): UsageDelta {
  const cached = reply.usage?.input_tokens_details?.cached_tokens ?? 0;
  const counts = { inputTokens: Math.max(0, (reply.usage?.input_tokens ?? 0) - cached), outputTokens: reply.usage?.output_tokens ?? 0, cacheReadTokens: cached, cacheWriteTokens: 0 };
  return { ...counts, costUsd: costUsd(servedModel, counts), servedModel, fallbackUsed: servedModel !== requestedModel && !servedModel.startsWith(requestedModel), refused };
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
