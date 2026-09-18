/**
 * The assistant on OpenAI or Google instead of Anthropic (AI_PROVIDER=openai|google with OPENAI_API_KEY or
 * GOOGLE_API_KEY). Plain HTTPS through the app's guarded fetch — the outbound allow-list, timeout and size limits
 * apply exactly as for any other outside call — and the same strict JSON answer schema, so every guard-rail in
 * index.ts (schema check, length, disclosure, moderation, proposals) works unchanged. Web search is Anthropic-only.
 */
import { z } from 'zod';
import { logger } from '../../lib/logger.ts';
import { config } from '../../config.ts';
import { MODERATION_PROMPT } from './prompt.ts';
import { AiUnavailableError, AnswerSchema, ModerationSchema, guardedFetch, requestTimeoutMs, type AiClient, type CompletionRequest, type CompletionResult, type ModerationScores } from './client.ts';

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** JSON schema in the strict shape both services accept: closed objects with every property required. */
export function strictJsonSchema(schema: z.ZodType): Record<string, unknown> {
  const walk = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(walk);
    if (!node || typeof node !== 'object') return node;
    const out: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(node as Record<string, unknown>)) {
      if (key === '$schema') continue;
      out[key] = walk(value);
    }
    if (out.type === 'object' && out.properties && typeof out.properties === 'object') {
      out.additionalProperties = false;
      out.required = Object.keys(out.properties as Record<string, unknown>);
    }
    return out;
  };
  return walk(z.toJSONSchema(schema, { target: 'draft-2020-12' })) as Record<string, unknown>;
}

function keyFor(name: 'OPENAI_API_KEY' | 'GOOGLE_API_KEY'): string | undefined {
  const key = process.env[name];
  return key && key.trim() !== '' ? key.trim() : undefined;
}

export function hasOpenAiKey(): boolean {
  return keyFor('OPENAI_API_KEY') !== undefined;
}
export function hasGoogleKey(): boolean {
  return keyFor('GOOGLE_API_KEY') !== undefined;
}

/** One JSON POST with the app's timeout; the answer's body, or an AiUnavailableError that never carries the key. */
async function postJson(provider: string, url: string, headers: Record<string, string>, body: unknown, fetchImpl: FetchLike): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetchImpl(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body), signal: AbortSignal.timeout(requestTimeoutMs()) });
  } catch (err) {
    if (err instanceof AiUnavailableError) throw err;
    const timeout = err instanceof Error && /timeout|timed out/i.test(err.message);
    const detail = timeout ? `the model did not answer within ${Math.round(requestTimeoutMs() / 1000)} seconds` : 'the model service could not be reached';
    logger.warn({ provider, detail }, 'the assistant could not reach the model');
    throw new AiUnavailableError(timeout ? 'timeout' : 'provider-error', detail);
  }
  const text = await res.text();
  if (!res.ok) {
    const detail = res.status === 401 || res.status === 403 ? 'the API key was refused by the model service' : res.status === 429 ? 'the model service is rate limiting this app' : res.status === 400 ? 'the model service rejected the request' : `the model service answered with status ${res.status}`;
    logger.warn({ provider, status: res.status, detail }, 'the assistant could not reach the model');
    throw new AiUnavailableError('provider-error', detail);
  }
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new AiUnavailableError('provider-error', 'the model service answered with something that was not JSON');
  }
}

// ---------------------------------------------------------------------------------------------------------
// OpenAI (Responses API)
// ---------------------------------------------------------------------------------------------------------

interface ResponsesReply {
  status?: string;
  incomplete_details?: { reason?: string } | null;
  output?: { type: string; content?: { type: string; text?: string; refusal?: string }[] }[];
  usage?: { input_tokens?: number; output_tokens?: number } | null;
}

function responsesText(reply: ResponsesReply): { text: string; refused: boolean } {
  let text = '';
  let refused = false;
  for (const item of reply.output ?? []) {
    if (item.type !== 'message') continue;
    for (const c of item.content ?? []) {
      if (c.type === 'output_text' && c.text) text += c.text;
      if (c.type === 'refusal') refused = true;
    }
  }
  return { text, refused };
}

export function openAiClient(fetchImpl: FetchLike = guardedFetch): AiClient {
  const key = keyFor('OPENAI_API_KEY');
  if (!key) throw new AiUnavailableError('not-configured', 'The assistant has no OpenAI API key configured.');
  const model = config.AI_MODEL;
  const url = 'https://api.openai.com/v1/responses';
  const headers = { authorization: `Bearer ${key}` };

  async function ask<T>(system: string, messages: CompletionRequest['messages'], schema: z.ZodType<T>, maxTokens: number): Promise<{ parsed: T | undefined; raw: string; stopReason: string; inputTokens: number; outputTokens: number }> {
    const reply = (await postJson('openai', url, headers, {
      model,
      instructions: system,
      input: messages.map((m) => ({ role: m.role, content: [{ type: m.role === 'assistant' ? 'output_text' : 'input_text', text: m.content }] })),
      text: { format: { type: 'json_schema', name: 'answer', schema: strictJsonSchema(schema), strict: true } },
      max_output_tokens: maxTokens,
      store: false,
    }, fetchImpl)) as ResponsesReply;
    const { text, refused } = responsesText(reply);
    const truncated = reply.status === 'incomplete' && reply.incomplete_details?.reason === 'max_output_tokens';
    let parsed: T | undefined;
    if (!refused && !truncated) {
      try {
        const checked = schema.safeParse(JSON.parse(text));
        parsed = checked.success ? checked.data : undefined;
      } catch {
        parsed = undefined;
      }
    }
    return { parsed, raw: text, stopReason: refused ? 'refusal' : truncated ? 'max_tokens' : 'end_turn', inputTokens: reply.usage?.input_tokens ?? 0, outputTokens: reply.usage?.output_tokens ?? 0 };
  }

  return {
    provider: 'openai',
    model,
    async complete(request): Promise<CompletionResult> {
      const r = await ask(request.system, request.messages, AnswerSchema, request.maxTokens);
      return { parsed: r.parsed, raw: r.raw, stopReason: r.stopReason, inputTokens: r.inputTokens, outputTokens: r.outputTokens };
    },
    async classify(text): Promise<ModerationScores> {
      const r = await ask(MODERATION_PROMPT, [{ role: 'user', content: `<text>\n${text}\n</text>` }], ModerationSchema, 256);
      if (!r.parsed) throw new AiUnavailableError('provider-error', 'the moderation check returned nothing usable');
      return r.parsed.categories;
    },
  };
}

// ---------------------------------------------------------------------------------------------------------
// Google (Gemini generateContent)
// ---------------------------------------------------------------------------------------------------------

interface GenerateReply {
  candidates?: { content?: { parts?: { text?: string; thought?: boolean }[] }; finishReason?: string }[];
  promptFeedback?: { blockReason?: string };
  usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number; thoughtsTokenCount?: number };
}

const GEMINI_REFUSALS = new Set(['SAFETY', 'PROHIBITED_CONTENT', 'BLOCKLIST', 'SPII', 'RECITATION']);

export function googleClient(fetchImpl: FetchLike = guardedFetch): AiClient {
  const key = keyFor('GOOGLE_API_KEY');
  if (!key) throw new AiUnavailableError('not-configured', 'The assistant has no Google API key configured.');
  const model = config.AI_MODEL;
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  const headers = { 'x-goog-api-key': key };

  async function ask<T>(system: string, messages: CompletionRequest['messages'], schema: z.ZodType<T>, maxTokens: number): Promise<{ parsed: T | undefined; raw: string; stopReason: string; inputTokens: number; outputTokens: number }> {
    const reply = (await postJson('google', url, headers, {
      systemInstruction: { parts: [{ text: system }] },
      contents: messages.map((m) => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
      generationConfig: { responseMimeType: 'application/json', responseJsonSchema: strictJsonSchema(schema), maxOutputTokens: maxTokens },
    }, fetchImpl)) as GenerateReply;
    const finish = reply.candidates?.[0]?.finishReason;
    const refused = reply.promptFeedback?.blockReason !== undefined || (finish !== undefined && GEMINI_REFUSALS.has(finish));
    const truncated = finish === 'MAX_TOKENS';
    const raw = (reply.candidates?.[0]?.content?.parts ?? [])
      .filter((p) => !p.thought && typeof p.text === 'string')
      .map((p) => p.text)
      .join('');
    let parsed: T | undefined;
    if (!refused && !truncated) {
      try {
        const checked = schema.safeParse(JSON.parse(raw));
        parsed = checked.success ? checked.data : undefined;
      } catch {
        parsed = undefined;
      }
    }
    const u = reply.usageMetadata;
    return { parsed, raw, stopReason: refused ? 'refusal' : truncated ? 'max_tokens' : 'end_turn', inputTokens: u?.promptTokenCount ?? 0, outputTokens: (u?.candidatesTokenCount ?? 0) + (u?.thoughtsTokenCount ?? 0) };
  }

  return {
    provider: 'google',
    model,
    async complete(request): Promise<CompletionResult> {
      const r = await ask(request.system, request.messages, AnswerSchema, request.maxTokens);
      return { parsed: r.parsed, raw: r.raw, stopReason: r.stopReason, inputTokens: r.inputTokens, outputTokens: r.outputTokens };
    },
    async classify(text): Promise<ModerationScores> {
      const r = await ask(MODERATION_PROMPT, [{ role: 'user', content: `<text>\n${text}\n</text>` }], ModerationSchema, 256);
      if (!r.parsed) throw new AiUnavailableError('provider-error', 'the moderation check returned nothing usable');
      return r.parsed.categories;
    },
  };
}
