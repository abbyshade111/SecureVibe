import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { SettingsStore } from '../../src/config.js';
import { providerFactory } from '../../src/llm/active-provider.js';

const dir = mkdtempSync(join(tmpdir(), 'sv-ai-switch-'));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe('the "Use AI" switch', () => {
  const env = { ANTHROPIC_API_KEY: 'placeholder-key-for-tests' };

  it('uses Claude when a key is set and the switch is on, and nothing when it is off', () => {
    const settings = new SettingsStore(join(dir, 'settings.json'));
    const get = providerFactory({ settings, aiDisabled: false }, { env });
    expect(get().name).toBe('anthropic');
    settings.update({ aiEnabled: false });
    expect(get().name).toBe('null');
    settings.update({ aiEnabled: true });
    expect(get().name).toBe('anthropic');
  });

  it('stays off when SECUREVIBE_AI=off, whatever the switch says', () => {
    const settings = new SettingsStore(join(dir, 'settings-2.json'));
    expect(providerFactory({ settings, aiDisabled: true }, { env })().name).toBe('null');
  });

  it('defaults to on', () => {
    expect(new SettingsStore(join(dir, 'settings-3.json')).get().aiEnabled).toBe(true);
  });
});
