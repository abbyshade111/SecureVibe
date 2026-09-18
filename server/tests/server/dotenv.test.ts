import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { loadDotEnv } from '../../src/config.js';

const dir = mkdtempSync(join(tmpdir(), 'sv-dotenv-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('loadDotEnv', () => {
  it('imports only SecureVibe keys, keeps existing values and treats blank entries as unset', () => {
    writeFileSync(
      join(dir, '.env'),
      ['# comment', 'ANTHROPIC_API_KEY=placeholder-value', 'SECUREVIBE_PORT=', 'SECUREVIBE_LOG_LEVEL="debug"', 'NODE_OPTIONS=--require evil', 'SECUREVIBE_HOME=/elsewhere'].join('\n'),
    );
    const env: NodeJS.ProcessEnv = { SECUREVIBE_HOME: '/already/set' };
    const loaded = loadDotEnv(dir, env);
    expect(loaded.sort()).toEqual(['ANTHROPIC_API_KEY', 'SECUREVIBE_LOG_LEVEL']);
    expect(env['SECUREVIBE_PORT']).toBeUndefined();
    expect(env['NODE_OPTIONS']).toBeUndefined();
    expect(env['SECUREVIBE_HOME']).toBe('/already/set');
    expect(env['SECUREVIBE_LOG_LEVEL']).toBe('debug');
  });

  it('accepts an Anthropic key pasted on its own line, but no other bare line', () => {
    writeFileSync(join(dir, '.env'), ['sk-ant-api00-placeholder_value', 'NOT_A_SETTING', 'sk-other-thing'].join('\n'));
    const env: NodeJS.ProcessEnv = {};
    expect(loadDotEnv(dir, env)).toEqual(['ANTHROPIC_API_KEY']);
    expect(env['ANTHROPIC_API_KEY']).toBe('sk-ant-api00-placeholder_value');
    expect(Object.keys(env)).toEqual(['ANTHROPIC_API_KEY']);
  });
});
