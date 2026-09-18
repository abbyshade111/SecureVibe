/**
 * The OpenAI provider through a fake fetch: no key, no network. Checked here: the request SecureVibe builds
 * (strict schema, effort, stateless replay, function tools) and how each kind of answer becomes a result.
 */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { OpenAiProvider, openAiEffort, toInputItems } from '../../src/llm/openai.js';
import type { AgentEvent, AgentTool } from '../../src/llm/types.js';

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
const req = { purpose: 'plan' as const, system: [{ text: 'You plan.', cache: true }, { text: 'Rules.' }], user: 'Plan it.', schema: Schema, effort: 'xhigh' as const, maxTokens: 2000, correlationId: 'c1', projectId: 'p_x' };

describe('OpenAI structured()', () => {
  it('sends a strict schema, the effort and the key header, and parses the answer', async () => {
    const message = { type: 'message', role: 'assistant', content: [{ type: 'output_text', text: JSON.stringify({ summary: 'ok', risky: false }) }] };
    const f = fakeFetch([{ model: 'gpt-5-2026-01-01', status: 'completed', output: [message], usage: { input_tokens: 1000, output_tokens: 50, input_tokens_details: { cached_tokens: 400 } } }]);
    const provider = new OpenAiProvider({ apiKey: 'sk-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const result = await provider.structured(req);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.data).toEqual({ summary: 'ok', risky: false });
    expect(result.usage.cacheReadTokens).toBe(400);
    expect(result.usage.inputTokens).toBe(600);
    expect(result.usage.costUsd).toBeGreaterThan(0);
    const call = f.calls[0]!;
    expect(call.url).toBe('https://api.openai.com/v1/responses');
    expect(call.headers['authorization']).toBe('Bearer sk-test');
    expect(call.body['instructions']).toBe('You plan.\n\nRules.');
    expect(call.body['reasoning']).toEqual({ effort: 'high' });
    expect(call.body['store']).toBe(false);
    const format = call.body['text']['format'];
    expect(format['strict']).toBe(true);
    expect(format['schema']['additionalProperties']).toBe(false);
    expect(format['schema']['required']).toEqual(['summary', 'risky']);
    expect(JSON.stringify(call.body)).not.toContain('sk-test');
  });

  it('turns a refusal, a truncated answer and a schema mismatch into honest failures', async () => {
    const f = fakeFetch([
      { output: [{ type: 'message', role: 'assistant', content: [{ type: 'refusal', refusal: 'no' }] }], usage: { input_tokens: 10, output_tokens: 1 } },
      { status: 'incomplete', incomplete_details: { reason: 'max_output_tokens' }, output: [], usage: { input_tokens: 10, output_tokens: 2000 } },
      { output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: '{"summary": 5}' }] }], usage: { input_tokens: 10, output_tokens: 5 } },
    ]);
    const provider = new OpenAiProvider({ apiKey: 'sk-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const a = await provider.structured(req);
    const b = await provider.structured(req);
    const c = await provider.structured(req);
    expect(a.ok === false && a.reason).toBe('refusal');
    expect(b.ok === false && b.reason).toBe('max_tokens');
    expect(c.ok === false && c.reason).toBe('invalid_output');
  });

  it('maps a rejected key to an account problem with a plain message', async () => {
    const f = fakeFetch([{ status: 401, body: { error: { message: 'Incorrect API key provided: sk-test' } } }]);
    const provider = new OpenAiProvider({ apiKey: 'sk-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const result = await provider.structured(req);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('error');
    expect(result.accountProblem).toBe(true);
    expect(result.message).toContain('OpenAI API key was not accepted');
    expect(result.message).not.toContain('sk-test');
  });
});

describe('OpenAI agentRun()', () => {
  it('runs function tools through the agent loop until done, replaying the model output statelessly', async () => {
    const written: string[] = [];
    const tools: AgentTool[] = [
      { name: 'write_file', description: 'write', inputSchema: z.object({ path: z.string(), content: z.string() }), run: async (input) => { written.push((input as { path: string }).path); return { content: 'ok' }; } },
      { name: 'done', description: 'done', inputSchema: z.object({ summary: z.string() }), run: async () => ({ content: 'done' }) },
    ];
    const reasoning = { type: 'reasoning', id: 'rs_1', encrypted_content: 'xyz', summary: [] };
    const f = fakeFetch([
      { model: 'gpt-5', status: 'completed', output: [reasoning, { type: 'function_call', call_id: 'call_1', name: 'write_file', arguments: JSON.stringify({ path: 'src/a.ts', content: 'x' }) }], usage: { input_tokens: 100, output_tokens: 20 } },
      { model: 'gpt-5', status: 'completed', output: [{ type: 'message', role: 'assistant', content: [{ type: 'output_text', text: 'Finishing.' }] }, { type: 'function_call', call_id: 'call_2', name: 'done', arguments: JSON.stringify({ summary: 'wrote a.ts' }) }], usage: { input_tokens: 200, output_tokens: 20 } },
    ]);
    const provider = new OpenAiProvider({ apiKey: 'sk-test', fetchImpl: f.fetchImpl, audit: { write: () => undefined } });
    const events: AgentEvent[] = [];
    const result = await provider.agentRun({ purpose: 'generate', system: [{ text: 'Build it.' }], user: 'Go.', tools, budget: { maxIterations: 5, maxUsd: 5, maxWallClockMs: 60_000, maxOutputTokens: 100_000 }, correlationId: 'c2', onEvent: (e) => events.push(e), abort: new AbortController().signal, effort: 'low' });
    expect(result.ok).toBe(true);
    expect(result.status).toBe('done');
    expect(written).toEqual(['src/a.ts']);
    expect(f.calls).toHaveLength(2);
    const first = f.calls[0]!.body;
    expect(first['tools'][0]).toMatchObject({ type: 'function', name: 'write_file', strict: true });
    expect(first['tools'][0]['parameters']['additionalProperties']).toBe(false);
    expect(first['include']).toEqual(['reasoning.encrypted_content']);
    expect(first['reasoning']).toEqual({ effort: 'low' });
    // The second turn replays the model's own items (reasoning included) and answers the call by id.
    const second = f.calls[1]!.body['input'] as Record<string, unknown>[];
    expect(second.some((i) => i['type'] === 'reasoning' && i['encrypted_content'] === 'xyz')).toBe(true);
    expect(second.some((i) => i['type'] === 'function_call_output' && i['call_id'] === 'call_1' && i['output'] === 'ok')).toBe(true);
    expect(result.usage.inputTokens).toBe(300);
  });
});

describe('helpers', () => {
  it('maps effort levels and builds input items', () => {
    expect(openAiEffort('max')).toBe('high');
    expect(openAiEffort('medium')).toBe('medium');
    expect(toInputItems({ role: 'user', blocks: [{ type: 'tool_result', toolUseId: 'c', content: 'boom', isError: true }] })).toEqual([{ type: 'function_call_output', call_id: 'c', output: 'ERROR: boom' }]);
  });
});
