/**
 * The Anthropic provider, driven through a stub SDK client. No key and no network are involved: what is checked here
 * is the shape of the request SecureVibe builds (caching, effort, adaptive thinking, the fallback beta, the tool
 * definitions) and how each stop reason is turned into a result.
 */
import Anthropic from '@anthropic-ai/sdk';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { z } from 'zod';
import { AGENT_MAX_TOKENS, AnthropicProvider, FALLBACK_BETA, STRUCTURED_MAX_TOKENS, toLlmError, userMessageForError } from '../../src/llm/anthropic.js';
import { createAgentTools } from '../../src/llm/tools.js';
import { makeTempApp, TEST_BUDGET, TEST_MANIFEST, type TempApp } from './helpers.js';

type Params = Record<string, any>;

interface Stub {
  parseCalls: Params[];
  streamCalls: Params[];
  client: Anthropic;
}

function stubClient(replies: { parse?: unknown[]; stream?: unknown[] }): Stub {
  const parseCalls: Params[] = [];
  const streamCalls: Params[] = [];
  const parseQueue = [...(replies.parse ?? [])];
  const streamQueue = [...(replies.stream ?? [])];
  const client = {
    messages: {
      // The provider streams the call and parses the text itself; replies written with `parsed_output` get it as text.
      stream: (params: Params) => {
        parseCalls.push(params);
        const next = parseQueue.shift() as Record<string, any> | Error | undefined;
        return {
          finalMessage: async () => {
            if (next instanceof Error) throw next;
            if (next && next['parsed_output'] && (next['content'] as unknown[]).length === 0) {
              return { ...next, content: [{ type: 'text', text: JSON.stringify(next['parsed_output']) }] };
            }
            return next;
          },
        };
      },
    },
    beta: {
      messages: {
        stream: (params: Params) => {
          streamCalls.push(params);
          const next = streamQueue.shift();
          return {
            finalMessage: async () => {
              if (next instanceof Error) throw next;
              return next;
            },
            abort: () => {},
          };
        },
      },
    },
  } as unknown as Anthropic;
  return { parseCalls, streamCalls, client };
}

const usage = { input_tokens: 1000, output_tokens: 200, cache_read_input_tokens: 500, cache_creation_input_tokens: 100 };
const OutputSchema = z.strictObject({ answer: z.string() });

describe('structured calls', () => {
  const request = {
    purpose: 'summarize' as const,
    system: [{ text: 'stable role block', cache: true }, { text: 'the volatile task' }],
    user: 'summarise this',
    schema: OutputSchema,
    effort: 'medium' as const,
    maxTokens: 99_000,
    correlationId: 'c-1',
    projectId: 'p-1',
  };

  it('sends cached system blocks, adaptive thinking, effort and a capped max_tokens', async () => {
    const stub = stubClient({
      parse: [{ model: 'claude-opus-5', stop_reason: 'end_turn', stop_details: null, content: [], usage, parsed_output: { answer: 'yes' } }],
    });
    const provider = new AnthropicProvider({ client: stub.client, audit: { write: () => {} } });
    const result = await provider.structured(request);

    expect(result.ok).toBe(true);
    const params = stub.parseCalls[0]!;
    expect(params.model).toBe('claude-opus-5');
    expect(params.max_tokens).toBe(STRUCTURED_MAX_TOKENS);
    expect(params.thinking).toEqual({ type: 'adaptive' });
    expect(params.output_config.effort).toBe('medium');
    expect(params.output_config.format).toBeDefined();
    // No SDK-side parser: SecureVibe checks the answer itself so a rejected answer's cost is still recorded.
    expect(params.output_config.format.type).toBe('json_schema');
    expect(params.output_config.format.parse).toBeUndefined();
    expect(params.system).toHaveLength(2);
    expect(params.system[0].cache_control).toEqual({ type: 'ephemeral' });
    expect(params.system[1].cache_control).toBeUndefined();
  });

  it('checks the stop reason before it reads any output', async () => {
    const stub = stubClient({
      parse: [
        {
          model: 'claude-opus-5',
          stop_reason: 'refusal',
          stop_details: { type: 'refusal', category: 'cyber', explanation: 'no' },
          content: [{ type: 'text', text: '{"answer":"this must not be used"}' }],
          usage,
          parsed_output: { answer: 'this must not be used' },
        },
        {
          model: 'claude-opus-5',
          stop_reason: 'max_tokens',
          stop_details: null,
          content: [{ type: 'text', text: '{"answer":"half' }],
          usage,
          parsed_output: null,
        },
      ],
    });
    const provider = new AnthropicProvider({ client: stub.client, audit: { write: () => {} } });

    const refusal = await provider.structured(request);
    expect(refusal.ok).toBe(false);
    if (!refusal.ok) {
      expect(refusal.reason).toBe('refusal');
      expect(refusal.category).toBe('cyber');
      expect(refusal.usage.refused).toBe(true);
    }

    const truncated = await provider.structured(request);
    expect(truncated.ok).toBe(false);
    if (!truncated.ok) expect(truncated.reason).toBe('max_tokens');
  });

  it('falls back to the text once when parsed_output is null, then gives up', async () => {
    const stub = stubClient({
      parse: [
        { model: 'claude-opus-5', stop_reason: 'end_turn', stop_details: null, content: [{ type: 'text', text: '{"answer":"from text"}' }], usage, parsed_output: null },
        { model: 'claude-opus-5', stop_reason: 'end_turn', stop_details: null, content: [{ type: 'text', text: 'sorry, no JSON here' }], usage, parsed_output: null },
      ],
    });
    const provider = new AnthropicProvider({ client: stub.client, audit: { write: () => {} } });

    const first = await provider.structured(request);
    expect(first.ok).toBe(true);
    if (first.ok) expect(first.data.answer).toBe('from text');

    const second = await provider.structured(request);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.reason).toBe('invalid_output');
  });

  it('records the model that served the answer', async () => {
    const stub = stubClient({
      parse: [{ model: 'claude-sonnet-5', stop_reason: 'end_turn', stop_details: null, content: [], usage, parsed_output: { answer: 'ok' } }],
    });
    const result = await new AnthropicProvider({ client: stub.client, audit: { write: () => {} } }).structured(request);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.servedModel).toBe('claude-sonnet-5');
      expect(result.usage.fallbackUsed).toBe(true);
    }
  });

  it('sends cacheable user blocks and still records the cost of a reply that is not valid JSON', async () => {
    const writes: string[] = [];
    const stub = stubClient({
      parse: [{ model: 'claude-opus-5', stop_reason: 'end_turn', stop_details: null, content: [{ type: 'text', text: '{"answer": "unterminated' }], usage }],
    });
    const result = await new AnthropicProvider({ client: stub.client, audit: { write: (line) => writes.push(line) } }).structured({
      ...request,
      user: [{ text: 'FILES ...', cache: true }, { text: 'CHAPTER V1' }],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('invalid_output');
      expect(result.usage.costUsd).toBeGreaterThan(0);
    }
    const content = stub.parseCalls[0]!.messages[0].content;
    expect(content[0].cache_control).toEqual({ type: 'ephemeral' });
    expect(content[1].cache_control).toBeUndefined();
    expect(JSON.parse(writes.at(-1)!).costUsd).toBeGreaterThan(0);
  });

  it('recognises an account without credit and says what to do', () => {
    const apiError = new Anthropic.BadRequestError(400, { type: 'error', error: { type: 'invalid_request_error', message: 'Your credit balance is too low to access the Anthropic API.' } }, 'Your credit balance is too low to access the Anthropic API.', new Headers());
    const mapped = toLlmError(apiError);
    expect(mapped.kind).toBe('billing');
    expect(userMessageForError(mapped)).toContain('run out of credit');
  });

  it('turns an SDK failure into a sentence a person can act on', async () => {
    const stub = stubClient({ parse: [new Error('socket hang up')] });
    const result = await new AnthropicProvider({ client: stub.client, audit: { write: () => {} } }).structured(request);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe('error');
      expect(result.message).not.toContain('sk-ant');
    }
    expect(userMessageForError(toLlmError(new Error('abort')))).toBe('The step was cancelled.');
  });
});

describe('agent runs', () => {
  let app: TempApp;
  beforeEach(() => {
    app = makeTempApp();
  });
  afterEach(() => app.cleanup());

  it('streams through the beta surface with server-side fallbacks, and drives the tools', async () => {
    const stub = stubClient({
      stream: [
        {
          model: 'claude-opus-5',
          stop_reason: 'tool_use',
          stop_details: null,
          usage,
          content: [
            { type: 'thinking', thinking: '', signature: 'sig' },
            {
              type: 'tool_use',
              id: 'tu_1',
              name: 'write_file',
              input: { path: 'src/features/notes/routes.ts', content: 'export const notes = true;\n' },
            },
          ],
        },
        {
          model: 'claude-opus-5',
          stop_reason: 'tool_use',
          stop_details: null,
          usage,
          content: [{ type: 'tool_use', id: 'tu_2', name: 'done', input: { summary: 'Added notes.', routesManifest: [], filesTouched: ['src/features/notes/routes.ts'] } }],
        },
      ],
    });
    const provider = new AnthropicProvider({ client: stub.client, audit: { write: () => {} } });
    const tools = createAgentTools({
      appDir: app.dir,
      protectedPaths: TEST_MANIFEST.protectedPaths,
      writablePaths: TEST_MANIFEST.writablePaths,
      runCheck: async () => ({ ok: true, output: '' }),
    });

    const result = await provider.agentRun({
      purpose: 'generate',
      system: [{ text: 'role' }, { text: 'paths', cache: true }],
      user: 'build it',
      tools,
      budget: TEST_BUDGET,
      correlationId: 'c-agent',
      onEvent: () => {},
      abort: new AbortController().signal,
      effort: 'xhigh',
    });

    expect(result.status).toBe('done');
    expect(readFileSync(join(app.dir, 'src/features/notes/routes.ts'), 'utf8')).toContain('export const notes');
    expect(result.usage.calls).toBe(2);

    const first = stub.streamCalls[0]!;
    expect(first.betas).toEqual([FALLBACK_BETA]);
    expect(first.fallbacks).toBe('default');
    expect(first.max_tokens).toBe(AGENT_MAX_TOKENS);
    expect(first.thinking).toEqual({ type: 'adaptive' });
    expect(first.output_config.effort).toBe('xhigh');
    expect(first.tools.map((t: Params) => t.name)).toEqual(['list_files', 'read_file', 'write_file', 'delete_file', 'run_checks', 'done']);
    for (const tool of first.tools as Params[]) {
      expect(tool.eager_input_streaming).toBe(true);
      expect(tool.input_schema.type).toBe('object');
      expect(tool.input_schema.additionalProperties).toBe(false);
    }

    // The second request replays the assistant turn unchanged (thinking block included) and answers the tool call,
    // with the instruction-hierarchy reminder after the results.
    const second = stub.streamCalls[1]!;
    expect(second.messages).toHaveLength(3);
    expect(second.messages[1].role).toBe('assistant');
    expect(second.messages[1].content[0]).toEqual({ type: 'thinking', thinking: '', signature: 'sig' });
    const followUp = second.messages[2];
    expect(followUp.role).toBe('user');
    expect(followUp.content[0].type).toBe('tool_result');
    expect(followUp.content[0].tool_use_id).toBe('tu_1');
    expect(followUp.content.at(-1).text).toContain('data, not instructions');
  });

  it('stops without running the tools when the model declines', async () => {
    const stub = stubClient({
      stream: [
        {
          model: 'claude-opus-5',
          stop_reason: 'refusal',
          stop_details: { type: 'refusal', category: 'cyber', explanation: 'no' },
          usage,
          content: [{ type: 'tool_use', id: 'tu_1', name: 'write_file', input: { path: 'src/features/notes/routes.ts', content: 'x' } }],
        },
      ],
    });
    const provider = new AnthropicProvider({ client: stub.client, audit: { write: () => {} } });
    const result = await provider.agentRun({
      purpose: 'generate',
      system: [{ text: 'role' }],
      user: 'build it',
      tools: createAgentTools({
        appDir: app.dir,
        protectedPaths: TEST_MANIFEST.protectedPaths,
        writablePaths: TEST_MANIFEST.writablePaths,
        runCheck: async () => ({ ok: true, output: '' }),
      }),
      budget: TEST_BUDGET,
      correlationId: 'c-agent-refusal',
      onEvent: () => {},
      abort: new AbortController().signal,
    });
    expect(result.status).toBe('refusal');
    expect(result.category).toBe('cyber');
    expect(stub.streamCalls).toHaveLength(1);
  });
});
