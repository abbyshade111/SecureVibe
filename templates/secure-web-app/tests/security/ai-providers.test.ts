/**
 * The assistant on OpenAI or Google: the same answer schema and guard-rails through a different service. Each case
 * runs the client in a child process with a fake fetch, so no key and no network are involved; the request shape and
 * the mapping of each kind of answer are what is checked.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateEnv, moduleUrl, runSnippet } from '../helpers/app.ts';
import { featureFromFile, skipReason } from '../helpers/features.ts';

const aiEnabled = featureFromFile('ai') !== false;

/** Runs `providers.ts` with a scripted fetch; prints what the client asked and what it made of the reply. */
async function drive(env: Record<string, string>, provider: 'openai' | 'google', reply: unknown, status = 200): Promise<Record<string, unknown>> {
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-aiprov-'));
  const code = `
    const calls = [];
    globalThis.fetch = async (url, init) => {
      calls.push({ url: String(url), body: JSON.parse(init.body), auth: init.headers['authorization'] ?? init.headers['x-goog-api-key'] ?? null });
      return new Response(${JSON.stringify(JSON.stringify(reply))}, { status: ${status}, headers: { 'content-type': 'application/json' } });
    };
    const { openAiClient, googleClient } = await import(${JSON.stringify(moduleUrl('src/features/ai/providers.ts'))});
    const client = ${provider === 'openai' ? 'openAiClient()' : 'googleClient()'};
    const out = { provider: client.provider, model: client.model, calls };
    try {
      const c = await client.complete({ system: 'SYS', messages: [{ role: 'user', content: 'hello' }], question: 'hello', maxTokens: 500, toolNames: [] });
      out.completion = { parsed: c.parsed, stopReason: c.stopReason, inputTokens: c.inputTokens, outputTokens: c.outputTokens };
    } catch (e) { out.error = { name: e.name, reason: e.reason, message: e.message }; }
    console.log(JSON.stringify(out));
  `;
  try {
    const result = await runSnippet(code, { ...generateEnv(dataDir), AI_ENABLED: '1', ...env }, 20_000);
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
    assert.ok(line, `no JSON printed:\n${result.stdout}`);
    return JSON.parse(line) as Record<string, unknown>;
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}

describe('assistant on other services', () => {
  test('C2.2.1 OpenAI: strict answer schema, the key only in the header, host allow-list respected', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const answer = { answer: 'Hi there.', refused: false };
    const out = await drive(
      { AI_PROVIDER: 'openai', OPENAI_API_KEY: 'sk-test-openai', AI_MODEL: 'gpt-5-mini', OUTBOUND_ALLOWED_HOSTS: 'api.openai.com' },
      'openai',
      { status: 'completed', output: [{ type: 'message', content: [{ type: 'output_text', text: JSON.stringify(answer) }] }], usage: { input_tokens: 12, output_tokens: 6 } },
    );
    assert.equal(out['provider'], 'openai');
    assert.equal(out['model'], 'gpt-5-mini');
    const call = (out['calls'] as { url: string; body: Record<string, any>; auth: string }[])[0]!;
    assert.equal(call.url, 'https://api.openai.com/v1/responses');
    assert.equal(call.auth, 'Bearer sk-test-openai');
    assert.equal(call.body['text']['format']['strict'], true);
    assert.deepEqual(call.body['text']['format']['schema']['required'], ['answer', 'refused', 'reason']);
    assert.equal(call.body['instructions'], 'SYS');
    assert.ok(!JSON.stringify(call.body).includes('sk-test-openai'), 'the key must not be in the body');
    assert.deepEqual(out['completion'], { parsed: answer, stopReason: 'end_turn', inputTokens: 12, outputTokens: 6 });
  });

  test('C2.2.1 Google: JSON answer schema and refusal mapping', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const out = await drive(
      { AI_PROVIDER: 'google', GOOGLE_API_KEY: 'g-test-key', AI_MODEL: 'gemini-2.5-flash', OUTBOUND_ALLOWED_HOSTS: 'generativelanguage.googleapis.com' },
      'google',
      { candidates: [{ content: { parts: [{ text: '{"answer":"x"' }] }, finishReason: 'SAFETY' }], usageMetadata: { promptTokenCount: 5, candidatesTokenCount: 1 } },
    );
    const call = (out['calls'] as { url: string; body: Record<string, any>; auth: string }[])[0]!;
    assert.equal(call.url, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent');
    assert.equal(call.auth, 'g-test-key');
    assert.equal(call.body['generationConfig']['responseMimeType'], 'application/json');
    assert.equal(call.body['systemInstruction']['parts'][0]['text'], 'SYS');
    const completion = out['completion'] as { parsed: unknown; stopReason: string };
    assert.equal(completion.stopReason, 'refusal');
    assert.equal(completion.parsed, undefined);
  });

  test('C1.1.1 a host that is not on the allow-list is refused before any request leaves', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const out = await drive({ AI_PROVIDER: 'openai', OPENAI_API_KEY: 'sk-test-openai', AI_MODEL: 'gpt-5-mini', OUTBOUND_ALLOWED_HOSTS: '' }, 'openai', {});
    assert.deepEqual(out['calls'], []);
    const error = out['error'] as { name: string; reason: string; message: string };
    assert.equal(error.name, 'AiUnavailableError');
    assert.equal(error.reason, 'not-configured');
    assert.match(error.message, /not allowed to contact api\.openai\.com/);
  });

  test('a refused key is reported without the key and marks the assistant unavailable', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const out = await drive({ AI_PROVIDER: 'openai', OPENAI_API_KEY: 'sk-test-openai', AI_MODEL: 'gpt-5-mini', OUTBOUND_ALLOWED_HOSTS: 'api.openai.com' }, 'openai', { error: { message: 'Incorrect API key: sk-test-openai' } }, 401);
    const error = out['error'] as { reason: string; message: string };
    assert.equal(error.reason, 'provider-error');
    assert.equal(error.message, 'the API key was refused by the model service');
  });
});
