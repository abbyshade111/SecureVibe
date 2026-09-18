/**
 * Web search (AI_WEB_SEARCH): off by default, and when on it is the model provider's own search tool — the app
 * makes no request of its own to any search engine, and its outbound allow-list is unchanged.
 */
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateEnv, moduleUrl, runSnippet } from '../helpers/app.ts';
import { featureFromFile, skipReason } from '../helpers/features.ts';

const aiEnabled = featureFromFile('ai') !== false;

/** Runs a snippet with the app's own config loaded from `env`, and returns what it printed as JSON. */
async function inspect(env: Record<string, string>): Promise<Record<string, unknown>> {
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-websearch-'));
  const code = `
    const { config } = await import(${JSON.stringify(moduleUrl('src/config.ts'))});
    const { webSearchTool, requestTimeoutMs } = await import(${JSON.stringify(moduleUrl('src/features/ai/client.ts'))});
    const { SYSTEM_PROMPT } = await import(${JSON.stringify(moduleUrl('src/features/ai/prompt.ts'))});
    console.log(JSON.stringify({
      tool: webSearchTool() ?? null,
      timeout: requestTimeoutMs(),
      outbound: config.outboundAllowedHosts,
      promptSaysCanSearch: SYSTEM_PROMPT.includes('search tool'),
      promptSaysCannotBrowse: SYSTEM_PROMPT.includes('cannot browse the internet'),
    }));
  `;
  try {
    const result = await runSnippet(code, { ...generateEnv(dataDir), ...env }, 20_000);
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
    assert.ok(line, `no JSON printed:\n${result.stdout}`);
    return JSON.parse(line) as Record<string, unknown>;
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}

/** Runs sourcesOf() on a message in a child process (with the app's config from a scratch env) and returns the results. */
async function sourcesFor(message: unknown): Promise<Record<string, unknown>> {
  const dataDir = mkdtempSync(join(tmpdir(), 'securevibe-websearch-'));
  const code = `
    const { sourcesOf, MAX_SOURCES } = await import(${JSON.stringify(moduleUrl('src/features/ai/client.ts'))});
    console.log(JSON.stringify({
      sources: sourcesOf(${JSON.stringify(message)}),
      uncited: sourcesOf({ content: [{ type: 'text', text: 'Sources: https://madeup.example' }] }),
      max: MAX_SOURCES,
    }));
  `;
  try {
    const result = await runSnippet(code, { ...generateEnv(dataDir), AI_ENABLED: '1' }, 20_000);
    assert.equal(result.code, 0, `${result.stdout}\n${result.stderr}`);
    const line = result.stdout.trim().split('\n').filter((l) => l.startsWith('{')).at(-1);
    assert.ok(line, `no JSON printed:\n${result.stdout}`);
    return JSON.parse(line) as Record<string, unknown>;
  } finally {
    rmSync(dataDir, { recursive: true, force: true });
  }
}

describe('ai web search', () => {
  test('C7.4.1 the sources shown come from the search results themselves, never from text the model wrote', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    // Run in a child process like the other cases: importing the client in this process would load the app's
    // logger with the app's own log file, which the test sandbox does not allow it to write.
    const message = {
      content: [
        {
          type: 'text',
          text: 'Two trials report a benefit.',
          citations: [
            { type: 'web_search_result_location', url: 'https://who.int/a', title: '  WHO guidance  ' },
            { type: 'web_search_result_location', url: 'https://who.int/a', title: 'duplicate' },
            { type: 'web_search_result_location', url: 'https://cdc.gov/b' },
            { type: 'web_search_result_location', url: 'javascript:alert(1)', title: 'not a web page' },
            { type: 'char_location', url: 'https://example.com/doc', title: 'not a web result' },
          ],
        },
        { type: 'text', text: 'Sources: https://madeup.example/invented' },
      ],
    };
    const out = await sourcesFor(message);
    assert.deepEqual(out['sources'], [
      { title: 'WHO guidance', url: 'https://who.int/a' },
      { title: 'cdc.gov', url: 'https://cdc.gov/b' },
    ]);
    // A reply with no citation metadata gets no source list, whatever its text claims.
    assert.deepEqual(out['uncited'], []);
    assert.equal(out['max'], 10);
  });

  test('C9.3.6 web search is off unless AI_WEB_SEARCH is set, and the assistant is told it cannot browse', async (t) => {
    // (An app whose own .env switches search on is covered by the "on" case below.)
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const off = await inspect({ AI_ENABLED: '1', AI_WEB_SEARCH: '0' });
    assert.equal(off['tool'], null);
    assert.equal(off['timeout'], 30_000);
    assert.equal(off['promptSaysCanSearch'], false);
    assert.equal(off['promptSaysCannotBrowse'], true);
  });

  test('C9.3.6 with search on, the provider\'s own tool is used, limited to the sites named, with no new outbound host', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const on = await inspect({
      AI_ENABLED: '1',
      AI_WEB_SEARCH: '1',
      AI_WEB_SEARCH_MAX_USES: '3',
      AI_WEB_SEARCH_DOMAINS: 'who.int, cdc.gov',
      OUTBOUND_ALLOWED_HOSTS: 'api.anthropic.com',
    });
    assert.deepEqual(on['tool'], { type: 'web_search_20260318', name: 'web_search', max_uses: 3, allowed_domains: ['who.int', 'cdc.gov'] });
    assert.equal(on['timeout'], 90_000);
    // Searching happens at the provider: the app still only talks to the provider itself.
    assert.deepEqual(on['outbound'], ['api.anthropic.com']);
    assert.equal(on['promptSaysCanSearch'], true);
    assert.equal(on['promptSaysCannotBrowse'], false);
  });

  test('C9.3.6 web search stays off when the AI feature itself is off', async (t) => {
    if (!aiEnabled) return t.skip(skipReason('ai'));
    const noAi = await inspect({ AI_ENABLED: '0', AI_WEB_SEARCH: '1' });
    assert.equal(noAi['tool'], null);
  });
});
