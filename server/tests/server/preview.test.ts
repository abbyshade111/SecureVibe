/** App preview: a real app started from the template, with throw-away data, stopped cleanly. Needs to listen. */
import { cpSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { deriveDesign } from '../../src/design/index.js';
import { loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { PreviewError, PreviewManager } from '../../src/preview/index.js';
import { ProjectStore } from '../../src/store/index.js';
import { habitTracker } from '../fixtures/design/profiles.js';

function get(port: number, path: string): Promise<number> {
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port, path, method: 'GET', timeout: 3_000 }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on('error', () => resolve(0));
    req.end();
  });
}

describe('app preview', () => {
  let home: string;
  let store: ProjectStore;
  let manager: PreviewManager;

  beforeAll(() => {
    home = mkdtempSync(join(tmpdir(), 'securevibe-preview-'));
    store = new ProjectStore(loadConfig({ ...process.env, SECUREVIBE_HOME: home }).paths.home);
    manager = new PreviewManager(store);
  });
  afterAll(() => {
    manager.stopAll();
    rmSync(home, { recursive: true, force: true });
  });

  it('refuses an app that has not been built', async () => {
    const project = store.create({ name: 'Empty', mode: 'guided', profile: habitTracker });
    const design = deriveDesign(habitTracker, { knowledge: loadKnowledge(), frameworks: loadFrameworks() });
    await expect(manager.start(project.id, design.buildSpec)).rejects.toBeInstanceOf(PreviewError);
    expect(manager.info(project.id).running).toBe(false);
  });

  it('runs the built app with a one-time sign-in and throws its data away when stopped', async () => {
    const project = store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const { appDir, dir } = store.paths(project.id);
    cpSync(join(loadConfig().paths.templateDir), appDir, { recursive: true, filter: (src) => !/[/\\](data[/\\]app\.db|\.env)$/.test(src) });
    const design = deriveDesign(habitTracker, { knowledge: loadKnowledge(), frameworks: loadFrameworks() });

    const info = await manager.start(project.id, design.buildSpec).catch((err: unknown) => {
      throw new Error(`${String(err)}\n${err instanceof PreviewError ? err.detail : ''}`);
    });
    expect(info.running).toBe(true);
    expect(info.url).toMatch(/^http:\/\/localhost:\d+\/preview-signin\?t=[\w-]{20,}$/);
    expect(info.email).toBe('preview-admin@example.com');
    expect(info.password?.length).toBeGreaterThanOrEqual(12);
    const port = Number(new URL(info.url!).port);
    // The link signs the visitor in: no password step for someone trying the app out.
    expect(await get(port, new URL(info.url!).pathname + new URL(info.url!).search)).toBe(303);
    expect(await get(port, '/healthz')).toBe(200);
    expect([200, 302, 303]).toContain(await get(port, '/'));

    // A second start returns the running preview instead of starting another.
    expect((await manager.start(project.id, design.buildSpec)).url).toBe(info.url);

    const previewDirs = () => readdirSync(join(dir, 'tmp')).filter((n) => n.startsWith('preview-'));
    expect(previewDirs()).toHaveLength(1);
    // The app's own data folder is untouched.
    expect(existsSync(join(appDir, 'data', 'app.db'))).toBe(false);

    expect(manager.stop(project.id)).toBe(true);
    expect(manager.info(project.id).running).toBe(false);
    for (let i = 0; i < 40 && (await get(port, '/healthz')) !== 0; i++) await new Promise((r) => setTimeout(r, 100));
    expect(await get(port, '/healthz')).toBe(0);
    for (let i = 0; i < 40 && previewDirs().length > 0; i++) await new Promise((r) => setTimeout(r, 100));
    expect(previewDirs()).toHaveLength(0);
  }, 120_000);
});
