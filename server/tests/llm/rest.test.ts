/** The shared HTTPS plumbing for the fetch-based providers: error kinds and the strict schema shape. */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { llmErrorForStatus, postJson, strictJsonSchema } from '../../src/llm/rest.js';

describe('llmErrorForStatus', () => {
  it('maps HTTP status and error bodies to the kinds the pipeline reacts to', () => {
    expect(llmErrorForStatus('OpenAI', 401, {}).kind).toBe('auth');
    expect(llmErrorForStatus('OpenAI', 429, { error: { code: 'insufficient_quota', message: 'quota' } }).kind).toBe('billing');
    expect(llmErrorForStatus('OpenAI', 429, { error: { message: 'slow down' } }).kind).toBe('rate-limit');
    expect(llmErrorForStatus('Google', 400, { error: { message: 'bad schema' } })).toMatchObject({ kind: 'bad-request', message: 'bad schema' });
    expect(llmErrorForStatus('Google', 503, {}).kind).toBe('api');
  });
});

describe('postJson', () => {
  it('reports a failed connection as a network problem and a canceled call as aborted', async () => {
    await expect(postJson('https://x', {}, {}, { service: 'OpenAI', timeoutMs: 1000, fetchImpl: async () => { throw new Error('ECONNREFUSED'); } })).rejects.toMatchObject({ kind: 'network' });
    const abort = new AbortController();
    abort.abort();
    await expect(postJson('https://x', {}, {}, { service: 'OpenAI', timeoutMs: 1000, abort: abort.signal, fetchImpl: async () => { throw new Error('aborted'); } })).rejects.toMatchObject({ kind: 'aborted' });
  });
});

describe('strictJsonSchema', () => {
  it('closes every object and requires every property, recursively', () => {
    const schema = z.object({ name: z.string(), inner: z.object({ n: z.number(), tags: z.array(z.object({ t: z.string() })) }) });
    const strict = strictJsonSchema(z.toJSONSchema(schema, { target: 'draft-2020-12' }) as Record<string, unknown>);
    expect(strict['$schema']).toBeUndefined();
    expect(strict['additionalProperties']).toBe(false);
    expect(strict['required']).toEqual(['name', 'inner']);
    const inner = (strict['properties'] as Record<string, Record<string, unknown>>)['inner']!;
    expect(inner['required']).toEqual(['n', 'tags']);
    const items = ((inner['properties'] as Record<string, Record<string, unknown>>)['tags']!['items']) as Record<string, unknown>;
    expect(items['additionalProperties']).toBe(false);
  });
});
