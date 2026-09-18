/**
 * Changing how an app looks: colour only, so it needs no rebuild and no approval — and it must leave every other
 * line of the app's settings file, including its secrets, exactly as it was.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { setEnvValue } from '../../src/generator/appearance.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('changing how an app looks', () => {
  let harness: TestHarness;
  let projectId: string;
  let appDir: string;
  let headers: Record<string, string>;

  beforeEach(async () => {
    harness = await buildHarness();
    projectId = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker }).id;
    appDir = harness.store.paths(projectId).appDir;
    mkdirSync(appDir, { recursive: true });
    writeFileSync(join(appDir, '.env'), ['# settings', 'APP_NAME=Habits', 'SESSION_SECRET=a-very-long-secret-value-here', 'APP_THEME=calm', 'PORT=3000'].join('\n') + '\n');
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken, Origin: 'http://127.0.0.1:4173' };
  });
  afterEach(() => harness?.cleanup());

  it('writes the chosen look into the built app and remembers it in the design', async () => {
    const res = await request(harness.server).put(`/api/projects/${projectId}/appearance`).set(headers).send({ theme: 'forest' });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ theme: 'forest', applied: true });
    const env = readFileSync(join(appDir, '.env'), 'utf8');
    expect(env).toContain('APP_THEME=forest');
    // Everything else is untouched, secrets included.
    expect(env).toContain('SESSION_SECRET=a-very-long-secret-value-here');
    expect(env).toContain('APP_NAME=Habits');
    expect(env).toContain('PORT=3000');
    expect(harness.store.mustGet(projectId).profile?.app?.theme).toBe('forest');
  });

  it('refuses a look it does not have, rather than writing it into the app', async () => {
    const res = await request(harness.server).put(`/api/projects/${projectId}/appearance`).set(headers).send({ theme: 'neon' });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(readFileSync(join(appDir, '.env'), 'utf8')).toContain('APP_THEME=calm');
  });

  it('adds the line when the app has no theme set yet, and leaves comments alone', () => {
    const file = join(appDir, '.env');
    writeFileSync(file, ['# APP_THEME=warm is only a comment', 'APP_NAME=Habits'].join('\n') + '\n');
    setEnvValue(file, 'APP_THEME', 'contrast');
    const lines = readFileSync(file, 'utf8').trim().split('\n');
    expect(lines).toEqual(['# APP_THEME=warm is only a comment', 'APP_NAME=Habits', 'APP_THEME=contrast']);
  });
});
