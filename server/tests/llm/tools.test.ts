/**
 * The tool layer is the boundary between a model's suggestion and the disk. These tests pin the refusals.
 */
import { existsSync, readFileSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  createAgentTools,
  matchesAny,
  resolveInApp,
  toolManifest,
  DoneInputSchema,
  MAX_READ_BYTES,
  type ToolContext,
} from '../../src/llm/tools.js';
import type { AgentTool, SecurityEvent } from '../../src/llm/types.js';
import { makeTempApp, TEST_MANIFEST, type TempApp } from './helpers.js';

describe('agent tools', () => {
  let app: TempApp;
  let events: SecurityEvent[];
  let tools: Map<string, AgentTool>;
  let touched: Set<string>;

  const ctxFor = (app: TempApp): ToolContext => ({
    appDir: app.dir,
    protectedPaths: TEST_MANIFEST.protectedPaths,
    writablePaths: TEST_MANIFEST.writablePaths,
    runCheck: async (check) => ({ ok: true, output: `${check} ok` }),
    onSecurityEvent: (e) => events.push(e),
    filesTouched: touched,
  });

  beforeEach(() => {
    app = makeTempApp();
    events = [];
    touched = new Set();
    tools = new Map(createAgentTools(ctxFor(app)).map((t) => [t.name, t]));
  });

  afterEach(() => app.cleanup());

  const run = async (name: string, input: unknown) => {
    const tool = tools.get(name)!;
    const parsed = tool.inputSchema.safeParse(input);
    expect(parsed.success, `input for ${name} should parse: ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
    return tool.run(parsed.success ? parsed.data : input);
  };

  it('writes a file inside a writable path', async () => {
    const result = await run('write_file', { path: 'src/features/notes/routes.ts', content: 'export const a = 1;\n' });
    expect(result.isError).toBeUndefined();
    expect(readFileSync(join(app.dir, 'src/features/notes/routes.ts'), 'utf8')).toContain('export const a = 1');
    expect(touched.has('src/features/notes/routes.ts')).toBe(true);
  });

  it('refuses to write outside the application folder', async () => {
    for (const path of ['../escape.ts', '../../escape.ts', '/tmp/securevibe-escape.ts', 'src/../../escape.ts']) {
      const result = await run('write_file', { path, content: 'x' });
      expect(result.isError, `${path} must be refused`).toBe(true);
      expect(result.securityEvent?.event).toBe('agent.path-denied');
    }
    expect(existsSync(join(app.parent, 'escape.ts'))).toBe(false);
    expect(events.every((e) => e.outcome === 'blocked')).toBe(true);
  });

  it('refuses to write a protected file, and allows the two documented exceptions', async () => {
    for (const path of ['src/security/authz.ts', 'package.json', 'docs/SECURITY.md', '.env', 'tests/security/authz.test.ts']) {
      const result = await run('write_file', { path, content: 'x' });
      expect(result.isError, `${path} must be refused`).toBe(true);
    }
    expect(readFileSync(join(app.dir, 'src/security/authz.ts'), 'utf8')).toContain('return false');

    const allowed = await run('write_file', { path: 'src/features/ai/prompt.ts', content: 'export const prompt = "hi";\n' });
    expect(allowed.isError).toBeUndefined();
  });

  it('refuses to read files that can hold secrets', async () => {
    for (const path of ['.env', '.env.example', 'certs/server.key', 'data/app.db']) {
      const result = await run('read_file', { path });
      expect(result.isError, `${path} must be refused`).toBe(true);
    }
    const ok = await run('read_file', { path: 'src/features/_example/routes.ts' });
    expect(ok.isError).toBeUndefined();
    expect(ok.untrustedSource).toBe('file:src/features/_example/routes.ts');
  });

  it('refuses to follow a symlink out of the application folder', async () => {
    const outside = join(app.parent, 'outside.txt');
    writeFileSync(outside, 'secret material', 'utf8');
    symlinkSync(outside, join(app.dir, 'src', 'features', 'link.ts'));
    const result = await run('read_file', { path: 'src/features/link.ts' });
    expect(result.isError).toBe(true);
    expect(result.content).not.toContain('secret material');
  });

  it('only deletes generated feature files', async () => {
    await run('write_file', { path: 'src/features/notes/routes.ts', content: 'x' });
    const deleted = await run('delete_file', { path: 'src/features/notes/routes.ts' });
    expect(deleted.isError).toBeUndefined();
    expect(existsSync(join(app.dir, 'src/features/notes/routes.ts'))).toBe(false);

    const refused = await run('delete_file', { path: 'tests/security/authz.test.ts' });
    expect(refused.isError).toBe(true);
    expect(existsSync(join(app.dir, 'tests/security/authz.test.ts'))).toBe(true);
  });

  it('lists files without node_modules, .git or data', async () => {
    const result = await run('list_files', { dir: null });
    expect(result.content).toContain('src/features/_example/routes.ts');
    expect(result.content).not.toContain('data/app.db');
  });

  it('refuses a file larger than the read limit', async () => {
    writeFileSync(join(app.dir, 'src/features/big.ts'), 'x'.repeat(MAX_READ_BYTES + 10), 'utf8');
    const result = await run('read_file', { path: 'src/features/big.ts' });
    expect(result.isError).toBe(true);
    expect(result.content).toContain('larger than');
  });

  it('runs only the three named checks and never a model-supplied command', async () => {
    const tool = tools.get('run_checks')!;
    expect(tool.inputSchema.safeParse({ check: 'typecheck' }).success).toBe(true);
    expect(tool.inputSchema.safeParse({ check: 'rm -rf /' }).success).toBe(false);
    expect(tool.inputSchema.safeParse({ command: 'npm install' }).success).toBe(false);
    const result = await run('run_checks', { check: 'test' });
    expect(result.content).toContain('test ok');
    expect(result.untrustedSource).toBe('tool-result:test');
  });

  it('validates the done input', () => {
    expect(DoneInputSchema.safeParse({ summary: 'ok', routesManifest: [], filesTouched: [] }).success).toBe(true);
    expect(DoneInputSchema.safeParse({ summary: 'ok' }).success).toBe(false);
    expect(
      DoneInputSchema.safeParse({
        summary: 'ok',
        routesManifest: [{ method: 'GET', path: '/notes', auth: 'user', roles: null, entity: null, kind: null, csrf: null, owner: null }],
        filesTouched: ['src/features/notes/routes.ts'],
      }).success,
    ).toBe(true);
    expect(
      DoneInputSchema.safeParse({
        summary: 'ok',
        routesManifest: [{ method: 'FETCH', path: '/notes', auth: 'user', roles: null, entity: null, kind: null, csrf: null, owner: null }],
        filesTouched: [],
      }).success,
    ).toBe(false);
  });

  it('describes every tool for the self-assessment', () => {
    const manifest = toolManifest({ writablePaths: TEST_MANIFEST.writablePaths, protectedPaths: TEST_MANIFEST.protectedPaths });
    expect(manifest.map((m) => m.name).sort()).toEqual(['delete_file', 'done', 'list_files', 'read_file', 'run_checks', 'write_file']);
    const write = manifest.find((m) => m.name === 'write_file')!;
    expect(write.mutates).toBe(true);
    expect(write.allowedPaths).toContain('tests/features/**');
    expect(write.deniedPaths).toContain('src/security/**');
  });
});

describe('path matching', () => {
  it('matches the manifest globs the way the contract describes', () => {
    const p = TEST_MANIFEST.protectedPaths;
    const w = TEST_MANIFEST.writablePaths;
    expect(matchesAny('src/security/authz.ts', p)).toBe(true);
    expect(matchesAny('src/security/deep/nested.ts', p)).toBe(true);
    expect(matchesAny('.env.local', p)).toBe(true);
    expect(matchesAny('src/features/ai/prompt.ts', p)).toBe(false); // the "!" exception re-opens it
    expect(matchesAny('src/features/notes/routes.ts', p)).toBe(false);

    expect(matchesAny('src/features/notes/routes.ts', w)).toBe(true);
    expect(matchesAny('src/db/migrations/101_notes.sql', w)).toBe(true);
    expect(matchesAny('src/db/migrations/001_users.sql', w)).toBe(false);
    expect(matchesAny('tests/security/authz.test.ts', w)).toBe(false);
  });

  it('rejects NUL bytes, backslashes and home-relative paths', () => {
    const app = makeTempApp();
    try {
      expect(resolveInApp(app.dir, 'src/feat ures/a.ts').ok).toBe(false);
      expect(resolveInApp(app.dir, 'src\\features\\a.ts').ok).toBe(false);
      expect(resolveInApp(app.dir, '~/secrets.txt').ok).toBe(false);
      expect(resolveInApp(app.dir, 'src/features/a.ts').ok).toBe(true);
    } finally {
      app.cleanup();
    }
  });
});
