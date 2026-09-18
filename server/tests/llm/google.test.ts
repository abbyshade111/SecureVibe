/** The Google (Gemini) provider through a fake fetch: request shape and result mapping, no key and no network. */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { GoogleProvider } from '../../src/llm/google.js';
import type { AgentTool } from '../../src/llm/types.js';

type Call = { url: string; body: Record<string, any>; headers: Record<string, string> };

function fakeFetch(replies: (Record<string, unknown> | { status: number; body: unknown })[]): { calls: Call[]; fetchImpl: (url: string, init: RequestInit) => Promise<Response> } {
  const calls: Call[] = [];
  const queue = [...replies];
  return {
    calls,
    fetchImpl: async (url, init) => {
      calls.push({ url, body: JSON.parse(String(init.body)), headers: init.headers as Record<string, string> });
      const next = queue.shift() ?? {};
      const status = 'status' in next && typeof next['status'] === 'number' && 'body' in next ? (next['status'] as number) : 200;
      const body = status === 200 ? next : (next as { body: unknown }).body;
      return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
    },
  };
}

const Schema = z.object({ summary: z.string(), risky: z.boolean() });
const req = { purpose: 'plan' as const, system: [{ text: 'You plan.' }], user: 'Plan it.', schema: Schema, effort: 'high' as const, maxTokens: 2000, correlationId: 'c1', projectId: 'p_x' };

describe('Google structured()', () => {
  it('asks for JSON matching the schema with the key in a header, and parses the answer', async () => {
    const f = fakeFetch([{ modelVersion: 'gemini-2.5-pro-001', candidates: [{ content: { parts: [{ text: JSON.stringify({ summary: 'ok', risky: true }) }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 900, candidatesTokenCount: 40, thoughtsTokenCount: 10, cachedContentTokenCount: 100 } }]);
    const provider = new GoogleProvider({ apiKey: 'g-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const result = await provider.structured(req);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data).toEqual({ summary: 'ok', risky: true });
    expect(result.usage).toMatchObject({ inputTokens: 800, outputTokens: 50, cacheReadTokens: 100 });
    const call = f.calls[0]!;
    expect(call.url).toBe('https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent');
    expect(call.headers['x-goog-api-key']).toBe('g-test');
    expect(call.body['generationConfig']['responseMimeType']).toBe('application/json');
    expect(call.body['generationConfig']['responseJsonSchema']['required']).toEqual(['summary', 'risky']);
    expect(call.body['systemInstruction']['parts'][0]['text']).toBe('You plan.');
    expect(JSON.stringify(call.body)).not.toContain('g-test');
  });

  it('treats a safety block as a refusal with its category, and MAX_TOKENS as truncation', async () => {
    const f = fakeFetch([
      { candidates: [{ content: { parts: [] }, finishReason: 'SAFETY' }], usageMetadata: { promptTokenCount: 10 } },
      { promptFeedback: { blockReason: 'PROHIBITED_CONTENT' }, usageMetadata: { promptTokenCount: 10 } },
      { candidates: [{ content: { parts: [{ text: '{"summ' }] }, finishReason: 'MAX_TOKENS' }], usageMetadata: { promptTokenCount: 10, candidatesTokenCount: 2000 } },
    ]);
    const provider = new GoogleProvider({ apiKey: 'g-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const a = await provider.structured(req);
    const b = await provider.structured(req);
    const c = await provider.structured(req);
    expect(a.ok === false && a.reason).toBe('refusal');
    expect(a.ok === false && a.category).toBe('safety');
    expect(b.ok === false && b.category).toBe('prohibited_content');
    expect(c.ok === false && c.reason).toBe('max_tokens');
  });

  it('maps quota exhaustion to an account problem', async () => {
    const f = fakeFetch([{ status: 429, body: { error: { code: 429, status: 'RESOURCE_EXHAUSTED', message: 'You exceeded your current quota' } } }]);
    const provider = new GoogleProvider({ apiKey: 'g-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const result = await provider.structured(req);
    expect(result.ok === false && result.accountProblem).toBe(true);
    expect(result.ok === false && result.message).toContain('Google account has no credit or quota left');
  });
});

describe('Google agentRun()', () => {
  it('declares functions, numbers the calls, and answers each by name', async () => {
    const written: string[] = [];
    const tools: AgentTool[] = [
      { name: 'write_file', description: 'write', inputSchema: z.object({ path: z.string(), content: z.string() }), run: async (input) => { written.push((input as { path: string }).path); return { content: 'ok' }; } },
      { name: 'done', description: 'done', inputSchema: z.object({ summary: z.string() }), run: async () => ({ content: 'done' }) },
    ];
    const f = fakeFetch([
      { candidates: [{ content: { role: 'model', parts: [{ thought: true, text: 'thinking' }, { functionCall: { name: 'write_file', args: { path: 'src/a.ts', content: 'x' } }, thoughtSignature: 'sig' }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 100, candidatesTokenCount: 20 } },
      { candidates: [{ content: { role: 'model', parts: [{ text: 'Finishing.' }, { functionCall: { name: 'done', args: { summary: 'wrote a.ts' } } }] }, finishReason: 'STOP' }], usageMetadata: { promptTokenCount: 200, candidatesTokenCount: 20 } },
    ]);
    const provider = new GoogleProvider({ apiKey: 'g-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const result = await provider.agentRun({ purpose: 'generate', system: [{ text: 'Build it.' }], user: 'Go.', tools, budget: { maxIterations: 5, maxUsd: 5, maxWallClockMs: 60_000, maxOutputTokens: 100_000 }, correlationId: 'c2', onEvent: () => undefined, abort: new AbortController().signal, effort: 'low' });
    expect(result.ok).toBe(true);
    expect(written).toEqual(['src/a.ts']);
    const first = f.calls[0]!.body;
    expect(first['tools'][0]['functionDeclarations'][0]).toMatchObject({ name: 'write_file' });
    expect(first['tools'][0]['functionDeclarations'][0]['parametersJsonSchema']['additionalProperties']).toBe(false);
    expect(first['generationConfig']['thinkingConfig']).toEqual({ thinkingBudget: 1024 });
    const second = f.calls[1]!.body['contents'] as { role: string; parts: Record<string, unknown>[] }[];
    // The model's own parts (thought signature included) come back unchanged, then the response by function name.
    expect(second.some((c) => c.role === 'model' && c.parts.some((p) => p['thoughtSignature'] === 'sig'))).toBe(true);
    const response = second.at(-1)!.parts[0]!['functionResponse'] as { name: string; response: { result: string } };
    expect(response).toEqual({ name: 'write_file', response: { result: 'ok' } });
  });
});
