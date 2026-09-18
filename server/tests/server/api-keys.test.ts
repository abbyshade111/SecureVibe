/** The owner's own AI-service keys: stored in .env, never returned, and the file stays owner-only. */
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ApiKeyError, keyStatuses, removeApiKey, setApiKey } from '../../src/security/api-keys.js';

const ANTHROPIC = `sk-ant-${'a'.repeat(40)}`;
const OPENAI = `sk-${'b'.repeat(40)}`;

describe('AI service keys', () => {
  let root: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'securevibe-keys-'));
    env = {};
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('writes a key to .env, keeps it owner-only, and uses it at once', () => {
    writeFileSync(join(root, '.env'), '# my settings\nSECUREVIBE_PORT=4173\n');
    const statuses = setApiKey(root, 'anthropic', ANTHROPIC, env);
    const file = readFileSync(join(root, '.env'), 'utf8');
    expect(file).toContain('# my settings');
    expect(file).toContain('SECUREVIBE_PORT=4173');
    expect(file).toContain(`ANTHROPIC_API_KEY=${ANTHROPIC}`);
    expect(statSync(join(root, '.env')).mode & 0o777).toBe(0o600);
    // In use without a restart.
    expect(env['ANTHROPIC_API_KEY']).toBe(ANTHROPIC);
    // Reported, but never the key itself.
    const anthropic = statuses.find((s) => s.service === 'anthropic')!;
    expect(anthropic).toMatchObject({ configured: true, endsWith: ANTHROPIC.slice(-4), usableForBuilds: true });
    expect(JSON.stringify(statuses)).not.toContain(ANTHROPIC);
  });

  it('replaces the line for that service and leaves other services alone', () => {
    setApiKey(root, 'anthropic', ANTHROPIC, env);
    setApiKey(root, 'openai', OPENAI, env);
    const replacement = `sk-ant-${'c'.repeat(40)}`;
    setApiKey(root, 'anthropic', replacement, env);
    const file = readFileSync(join(root, '.env'), 'utf8');
    expect(file).toContain(`ANTHROPIC_API_KEY=${replacement}`);
    expect(file).not.toContain(ANTHROPIC);
    expect(file).toContain(`OPENAI_API_KEY=${OPENAI}`);
    expect(file.split('\n').filter((l) => l.startsWith('ANTHROPIC_API_KEY='))).toHaveLength(1);
  });

  it('removes a key from the file and the environment', () => {
    setApiKey(root, 'anthropic', ANTHROPIC, env);
    const statuses = removeApiKey(root, 'anthropic', env);
    expect(readFileSync(join(root, '.env'), 'utf8')).not.toContain('ANTHROPIC_API_KEY');
    expect(env['ANTHROPIC_API_KEY']).toBeUndefined();
    expect(statuses.find((s) => s.service === 'anthropic')!.configured).toBe(false);
  });

  it('refuses something that is not a key for that service', () => {
    for (const bad of ['', '   ', 'hello world', 'sk-ant-short', OPENAI]) {
      expect(() => setApiKey(root, 'anthropic', bad, env), bad).toThrow(ApiKeyError);
    }
    // Nothing was written at all: a refused key never creates or touches the file.
    expect(existsSync(join(root, '.env'))).toBe(false);
  });

  it('replaces a bare key line, the form SecureVibe has always accepted', () => {
    writeFileSync(join(root, '.env'), `${ANTHROPIC}\n`);
    // The bare line counts as "in the file", so Settings may replace it.
    const bare = keyStatuses(root, { ANTHROPIC_API_KEY: ANTHROPIC }).find((s2) => s2.service === 'anthropic')!;
    expect(bare.configured).toBe(true);
    expect(bare.fromEnvironment).toBeUndefined();
    const replacement = `sk-ant-${'d'.repeat(40)}`;
    setApiKey(root, 'anthropic', replacement, env);
    const file = readFileSync(join(root, '.env'), 'utf8');
    expect(file).toBe(`ANTHROPIC_API_KEY=${replacement}\n`);
  });

  it('says when a key comes from the environment rather than the file', () => {
    const statuses = keyStatuses(root, { ANTHROPIC_API_KEY: ANTHROPIC });
    expect(statuses.find((s) => s.service === 'anthropic')).toMatchObject({ configured: true, fromEnvironment: true });
  });
});
