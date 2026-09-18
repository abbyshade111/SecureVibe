/**
 * Google provider (Gemini `generateContent` over plain HTTPS; no SDK).
 *
 *  - `structured()` asks for JSON matching the schema (`responseJsonSchema`), then checks the finish reason and
 *    parses the answer with zod.
 *  - `agentRun()` supplies one model turn to the shared agent loop: function declarations with JSON-schema
 *    parameters, function calls mapped to the loop's tool blocks (Gemini has no call ids, so SecureVibe numbers
 *    them and answers with the function's name), the model's own parts replayed unchanged.
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
import type { AgentRunRequest, AgentRunResult, AgentTool, Effort, LlmProvider, ProviderName, StructuredRequest, StructuredResult, UsageDelta } from './types.js';
import { systemText } from './openai.js';

export const DEFAULT_GOOGLE_MODEL = 'gemini-2.5-pro';
export const GOOGLE_STRUCTURED_MAX_TOKENS = 32_000;
export const GOOGLE_AGENT_MAX_TOKENS = 64_000;
const DEFAULT_TIMEOUT_MS = 20 * 60_000;
const SERVICE = 'Google';

export interface GoogleProviderOptions {
  model?: string;
  apiKey?: string;
  baseUrl?: string;
  fetchImpl?: FetchLike;
  timeoutMs?: number;
  injectionPatterns?: InjectionPatterns;
  defaultEffort?: Effort;
  audit?: AuditOptions;
}

interface Part {
  text?: string;
  thought?: boolean;
  thoughtSignature?: string;
  functionCall?: { name: string; args?: unknown };
  functionResponse?: { name: string; response: unknown };
}

interface GenerateReply {
  modelVersion?: string;
  candidates?: { content?: { role?: string; parts?: Part[] }; finishReason?: string }[];
  promptFeedback?: { blockReason?: string };
  usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number; thoughtsTokenCount?: number; cachedContentTokenCount?: number };
}

/** Finish reasons that mean the model declined rather than finished. */
const REFUSAL_REASONS = new Set(['SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII', 'RECITATION']);

export class GoogleProvider implements LlmProvider {
  readonly name: ProviderName = 'google';
  readonly model: string;
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike | undefined;
  private readonly timeoutMs: number;
  private readonly patterns: InjectionPatterns;
  private readonly defaultEffort: Effort;
  private readonly auditOptions: AuditOptions;
  /** Gemini function calls carry no id: SecureVibe numbers them and remembers the name for the response. */
  private callNames = new Map<string, string>();
  private calls = 0;

  constructor(opts: GoogleProviderOptions = {}) {
    this.model = opts.model ?? DEFAULT_GOOGLE_MODEL;
    this.apiKey = opts.apiKey ?? process.env['GOOGLE_API_KEY'] ?? '';
    this.baseUrl = (opts.baseUrl ?? 'https://generativelanguage.googleapis.com/v1beta').replace(/\/$/, '');
    this.fetchImpl = opts.fetchImpl;
    this.timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.patterns = opts.injectionPatterns ?? loadDefaultInjectionPatterns();
    this.defaultEffort = opts.defaultEffort ?? 'high';
    this.auditOptions = opts.audit ?? {};
  }

  private post(body: unknown, abort?: AbortSignal): Promise<GenerateReply> {
    return postJson(`${this.baseUrl}/models/${encodeURIComponent(this.model)}:generateContent`, { 'x-goog-api-key': this.apiKey }, body, {
      ...(this.fetchImpl ? { fetchImpl: this.fetchImpl } : {}),
      timeoutMs: this.timeoutMs,
      ...(abort ? { abort } : {}),
      service: SERVICE,
    }) as Promise<GenerateReply>;
  }

  async structured<T>(req: StructuredRequest<T>): Promise<StructuredResult<T>> {
    const maxTokens = Math.min(req.maxTokens || GOOGLE_STRUCTURED_MAX_TOKENS, GOOGLE_STRUCTURED_MAX_TOKENS);
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId, req.runId);
    const promptHash = hashJson({ system: req.system, user: req.user });
    const userText = typeof req.user === 'string' ? req.user : systemText(req.user);
    try {
      const reply = await this.post(
        {
          systemInstruction: { parts: [{ text: systemText(req.system) }] },
          contents: [{ role: 'user', parts: [{ text: userText }] }],
          generationConfig: {
            responseMimeType: 'application/json',
            responseJsonSchema: strictJsonSchema(z.toJSONSchema(req.schema as z.ZodType, { target: 'draft-2020-12' }) as Record<string, unknown>),
            maxOutputTokens: maxTokens,
          },
        },
        req.abort,
      );
      const servedModel = reply.modelVersion ?? this.model;
      const finish = finishOf(reply);
      const refused = finish.kind === 'refusal';
      const usage = usageOf(reply, servedModel, this.model, refused);
      auditCall(context, auditCallFrom(usage, { stopReason: finish.kind === 'refusal' ? 'refusal' : finish.kind === 'max_tokens' ? 'max_tokens' : 'end_turn', ...(finish.category ? { stopCategory: finish.category } : {}), promptHash, responseHash: hashJson(reply.candidates ?? []) }));
      storeExchange({ correlationId: req.correlationId, projectId: req.projectId, ...(req.runId ? { runId: req.runId } : {}), purpose: req.purpose, prompt: { system: req.system, user: req.user }, response: reply.candidates ?? [] }, this.auditOptions);

      if (refused) return { ok: false, reason: 'refusal', ...(finish.category ? { category: finish.category } : {}), message: refusalMessage(finish.category), usage };
      if (finish.kind === 'max_tokens') return { ok: false, reason: 'max_tokens', message: MAX_TOKENS_MESSAGE, usage };
      const parsed = safeJsonParse(textOf(reply));
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
    const declarations = req.tools.map(functionDeclaration);
    const system = systemText(req.system);
    const effort = req.effort ?? this.defaultEffort;
    const context = this.auditContext(req.purpose, req.correlationId, req.projectId ?? 'unknown', req.runId);
    this.callNames.clear();
    this.calls = 0;
    try {
      return await runAgentLoop(req, {
        provider: this.name,
        model: this.model,
        screen: (text) => screenText(text, this.patterns),
        onTurnAudit: (audit) =>
          auditCall(context, auditCallFrom(audit.usage, { stopReason: audit.stopReason, ...(audit.stopCategory ? { stopCategory: audit.stopCategory } : {}), promptHash: audit.promptHash ?? '', responseHash: audit.responseHash ?? '', injectionFlags: audit.injectionFlags, pathDenials: audit.pathDenials, iteration: audit.iteration, durationMs: audit.durationMs })),
        onStop: (info) => {
          if (!info.budgetStop) return;
          auditCall(context, { servedModel: this.model, stopReason: 'budget', fallbackUsed: false, inputTokens: 0, outputTokens: 0, cacheRead: 0, cacheWrite: 0, costUsd: 0, promptHash: '', responseHash: '', budgetStop: info.budgetStop, iteration: info.iterations });
        },
        runTurn: async ({ messages }) => this.runTurn(messages, system, declarations, effort, req.abort),
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

  private async runTurn(messages: AgentMessage[], system: string, declarations: unknown[], effort: Effort, abort: AbortSignal): Promise<AgentTurn> {
    const reply = await this.post(
      {
        systemInstruction: { parts: [{ text: system }] },
        contents: messages.map((m) => this.toContent(m)),
        tools: [{ functionDeclarations: declarations }],
        generationConfig: { maxOutputTokens: GOOGLE_AGENT_MAX_TOKENS, ...(effort === 'low' ? { thinkingConfig: { thinkingBudget: 1024 } } : {}) },
      },
      abort,
    );
    const servedModel = reply.modelVersion ?? this.model;
    const parts = reply.candidates?.[0]?.content?.parts ?? [];
    const blocks: AgentBlock[] = [];
    for (const part of parts) {
      if (part.thought) continue;
      if (typeof part.text === 'string' && part.text !== '') blocks.push({ type: 'text', text: part.text });
      if (part.functionCall) {
        const id = `${part.functionCall.name}#${++this.calls}`;
        this.callNames.set(id, part.functionCall.name);
        blocks.push({ type: 'tool_use', id, name: part.functionCall.name, input: part.functionCall.args ?? {} });
      }
    }
    const finish = finishOf(reply);
    const stopReason: AgentStopReason = finish.kind === 'refusal' ? 'refusal' : finish.kind === 'max_tokens' ? 'max_tokens' : blocks.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn';
    const turn: AgentTurn = {
      blocks,
      raw: parts,
      stopReason,
      usage: usageOf(reply, servedModel, this.model, finish.kind === 'refusal'),
      promptHash: hashText(`${hashText(system)}:${hashJson(messages.map((m) => m.role))}:${messages.length}`),
      responseHash: hashJson(parts),
    };
    return finish.category ? { ...turn, stopCategory: finish.category } : turn;
  }

  private toContent(message: AgentMessage): { role: 'user' | 'model'; parts: Part[] } {
    if (message.role === 'assistant') {
      const raw = message.raw as Part[] | undefined;
      if (raw && raw.length > 0) return { role: 'model', parts: raw };
      return {
        role: 'model',
        parts: message.blocks.flatMap((b): Part[] => {
          if (b.type === 'text') return [{ text: b.text }];
          if (b.type === 'tool_use') return [{ functionCall: { name: b.name, args: b.input ?? {} } }];
          return [];
        }),
      };
    }
    return {
      role: 'user',
      parts: message.blocks.flatMap((b): Part[] => {
        if (b.type === 'text') return [{ text: b.text }];
        if (b.type === 'tool_result') {
          const name = this.callNames.get(b.toolUseId) ?? b.toolUseId.split('#')[0] ?? 'tool';
          return [{ functionResponse: { name, response: b.isError ? { error: b.content } : { result: b.content } } }];
        }
        return [];
      }),
    };
  }
}

export function functionDeclaration(tool: AgentTool): unknown {
  return { name: tool.name, description: tool.description, parametersJsonSchema: strictJsonSchema(z.toJSONSchema(tool.inputSchema, { io: 'input', target: 'draft-2020-12' }) as Record<string, unknown>) };
}

function textOf(reply: GenerateReply): string {
  return (reply.candidates?.[0]?.content?.parts ?? [])
    .filter((p) => !p.thought && typeof p.text === 'string')
    .map((p) => p.text)
    .join('');
}

function finishOf(reply: GenerateReply): { kind: 'end' | 'max_tokens' | 'refusal'; category?: string } {
  const blocked = reply.promptFeedback?.blockReason;
  if (blocked) return { kind: 'refusal', category: blocked.toLowerCase() };
  const reason = reply.candidates?.[0]?.finishReason;
  if (reason === 'MAX_TOKENS') return { kind: 'max_tokens' };
  if (reason && REFUSAL_REASONS.has(reason)) return { kind: 'refusal', category: reason.toLowerCase() };
  return { kind: 'end' };
}

export function usageOf(reply: GenerateReply, servedModel: string, requestedModel: string, refused: boolean): UsageDelta {
  const u = reply.usageMetadata;
  const cached = u?.cachedContentTokenCount ?? 0;
  const counts = { inputTokens: Math.max(0, (u?.promptTokenCount ?? 0) - cached), outputTokens: (u?.candidatesTokenCount ?? 0) + (u?.thoughtsTokenCount ?? 0), cacheReadTokens: cached, cacheWriteTokens: 0 };
  return { ...counts, costUsd: costUsd(servedModel, counts), servedModel, fallbackUsed: !servedModel.startsWith(requestedModel), refused };
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

