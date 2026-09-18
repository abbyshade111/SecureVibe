/**
 * The agent loop, driven by the scripted provider through every failure mode SecureVibe has to survive
 * (DESIGN §13 item 13). The rule these tests protect: a refused or truncated turn never reaches the disk.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateApp } from '../../src/llm/flows/generate.js';
import { ScriptedProvider } from '../../src/llm/scripted.js';
import type { AgentEvent } from '../../src/llm/types.js';
import { collectEvents, FIXTURE_DIR, makeDesign, makeTempApp, TEST_BUDGET, TEST_MANIFEST, type TempApp } from './helpers.js';

function providerFor(scenario: string): ScriptedProvider {
  return new ScriptedProvider({ dir: FIXTURE_DIR, scenario });
}

describe('generation agent', () => {
  let app: TempApp;
  let events: AgentEvent[];
  let onEvent: (e: AgentEvent) => void;
  const checksRun: string[] = [];

  beforeEach(() => {
    app = makeTempApp();
    const collected = collectEvents();
    events = collected.events;
    onEvent = collected.onEvent;
    checksRun.length = 0;
  });

  afterEach(() => app.cleanup());

  const generate = (scenario: string, budget = TEST_BUDGET) =>
    generateApp(providerFor(scenario), {
      appDir: app.dir,
      design: makeDesign(),
      manifest: TEST_MANIFEST,
      brief: 'Build a repair-job tracker with one record type: repair-job.',
      description: 'I run a small bike repair shop and need to track repair jobs.',
      budget,
      runCheck: async (check) => {
        checksRun.push(check);
        return { ok: true, output: `${check}: no problems found` };
      },
      onEvent,
      abort: new AbortController().signal,
      runId: 'run-test',
      projectId: 'project-test',
    });

  it('writes the feature, runs the checks and reports what it built', async () => {
    const result = await generate('generate-happy-path');

    expect(result.ok).toBe(true);
    expect(result.status).toBe('done');
    expect(existsSync(join(app.dir, 'src/features/notes/routes.ts'))).toBe(true);
    expect(existsSync(join(app.dir, 'tests/features/notes.test.ts'))).toBe(true);
    expect(result.filesTouched).toEqual(['src/features/notes/routes.ts', 'tests/features/notes.test.ts']);
    expect(result.routesManifest[0]?.path).toBe('/notes');
    expect(checksRun).toEqual(['typecheck']);
    expect(result.pathDenials).toBe(0);
    expect(result.usage.calls).toBe(5);
    expect(result.usage.estimatedCostUsd).toBeGreaterThan(0);
    expect(result.summary).toContain('notes');
    expect(events.some((e) => e.type === 'tool_use')).toBe(true);
    expect(events.at(-1)).toMatchObject({ type: 'stop', status: 'done' });
  });

  it('writes nothing when the model declines before it starts', async () => {
    const result = await generate('refusal-before-output');

    expect(result.status).toBe('refusal');
    expect(result.ok).toBe(false);
    expect(result.failure?.options).toEqual(['change-answers', 'retry']);
    expect(result.message).toContain('declined');
    expect(result.message).toContain('cyber');
    expect(existsSync(join(app.dir, 'src/features/notes/routes.ts'))).toBe(false);
    expect(result.filesTouched).toEqual([]);
  });

  it('does not run the tool calls of a turn that ends in a refusal', async () => {
    const result = await generate('refusal-mid-stream');

    expect(result.status).toBe('refusal');
    // The first turn finished normally, so its file is kept…
    expect(existsSync(join(app.dir, 'src/features/notes/routes.ts'))).toBe(true);
    // …but nothing from the refusing turn was executed.
    expect(existsSync(join(app.dir, 'src/features/notes/service.ts'))).toBe(false);
    expect(result.filesTouched).toEqual(['src/features/notes/routes.ts']);
  });

  it('never writes a file whose content was cut short by the token limit', async () => {
    const result = await generate('max-tokens-tool-input');

    expect(result.status).toBe('max_tokens');
    expect(existsSync(join(app.dir, 'src/features/notes/routes.ts'))).toBe(false);
    expect(result.filesTouched).toEqual([]);
    expect(result.message).toContain('half-written');
  });

  it('refuses path escapes, keeps going, and counts the denials', async () => {
    const result = await generate('path-traversal');

    expect(result.status).toBe('done');
    expect(result.pathDenials).toBe(3);
    expect(existsSync(join(app.parent, 'outside', 'evil.ts'))).toBe(false);
    expect(existsSync('/tmp/securevibe-escape.ts')).toBe(false);
    expect(existsSync(join(app.dir, 'src/features/notes/routes.ts'))).toBe(true);

    const denials = events.filter((e) => e.type === 'security' && e.event === 'agent.path-denied');
    expect(denials).toHaveLength(3);
  });

  it('refuses to change the tested security baseline', async () => {
    const result = await generate('protected-path');

    expect(result.status).toBe('done');
    expect(result.pathDenials).toBe(3);
    expect(readFileSync(join(app.dir, 'src/security/authz.ts'), 'utf8')).toContain('return false');
    expect(readFileSync(join(app.dir, 'package.json'), 'utf8')).not.toContain('lodash');
    expect(existsSync(join(app.dir, 'tests/security/authz.test.ts'))).toBe(true);
    expect(result.filesTouched).toEqual(['src/features/notes/routes.ts']);
  });

  it('stops at the execution budget and keeps what was written', async () => {
    const result = await generate('over-budget', { ...TEST_BUDGET, maxIterations: 3 });

    expect(result.status).toBe('budget');
    expect(result.budgetStop).toBe('iterations');
    expect(result.iterations).toBe(3);
    expect(result.message).toContain('3 working steps');
    expect(result.failure?.options).toContain('retry');
  });

  it('stops at the spending limit', async () => {
    const result = await generate('over-budget', { ...TEST_BUDGET, maxUsd: 0.05 });

    expect(result.status).toBe('budget');
    expect(result.budgetStop).toBe('usd');
    expect(result.usage.estimatedCostUsd).toBeGreaterThan(0);
  });

  it('flags a tool result that tries to give the AI new instructions', async () => {
    const result = await generate('injected-tool-result');

    expect(result.status).toBe('done');
    expect(result.injectionFlags).toBeGreaterThanOrEqual(1);
    const flagged = events.find((e) => e.type === 'security' && e.event === 'agent.injection-flagged');
    expect(flagged).toBeDefined();

    // The file contents reached the model wrapped as data, with the screening note attached.
    const toolResult = events.find((e) => e.type === 'tool_result' && e.tool === 'read_file');
    expect(toolResult).toMatchObject({ type: 'tool_result' });
    if (toolResult?.type === 'tool_result') {
      expect(toolResult.preview).toContain('<untrusted_data source="file:src/features/imported/notes.ts">');
      expect(toolResult.preview).toContain('SecureVibe screening');
    }
    // And nothing in the baseline was touched.
    expect(readFileSync(join(app.dir, 'src/security/authz.ts'), 'utf8')).toContain('return false');
  });

  it('can be cancelled', async () => {
    const controller = new AbortController();
    controller.abort();
    const result = await generateApp(providerFor('generate-happy-path'), {
      appDir: app.dir,
      design: makeDesign(),
      manifest: TEST_MANIFEST,
      brief: 'Build it.',
      budget: TEST_BUDGET,
      runCheck: async () => ({ ok: true, output: '' }),
      onEvent,
      abort: controller.signal,
    });
    expect(result.status).toBe('aborted');
    expect(result.filesTouched).toEqual([]);
  });
});
