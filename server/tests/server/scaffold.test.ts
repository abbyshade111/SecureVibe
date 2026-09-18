/** Runs the real scaffold step against templates/secure-web-app (skipped if that folder is not present). */
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { deriveDesign, loadFrameworks, loadKnowledge } from '../../src/integration.js';
import { REPO_ROOT } from '../../src/config.js';
import { computeProtectedFileHashes, manifestFeatureFlags, scaffoldApp } from '../../src/generator/index.js';
import { habitTracker, teamInventory } from '../fixtures/design/profiles.js';

const templateDir = join(REPO_ROOT, 'templates', 'secure-web-app');
const templateExists = existsSync(join(templateDir, 'securevibe.manifest.json'));

describe.skipIf(!templateExists)('generator/scaffold against the real template', () => {
  it('copies the template, applies feature toggles, and writes the generated app\'s own config files', async () => {
    const projectDir = mkdtempSync(join(tmpdir(), 'securevibe-scaffold-'));
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(habitTracker, { knowledge, frameworks });
      const appDir = join(projectDir, 'app');

      const result = await scaffoldApp({
        templateDir,
        projectDir,
        appDir,
        design,
        profile: habitTracker,
        buildSpec: design.buildSpec,
        settings: { model: 'claude-opus-5', generationEffort: 'high', reviewEffort: 'medium', defaultSpendingCapUsd: 15, maxFixRounds: 2, storeFullPrompts: true, aiEnabled: true, saveCredits: false },
        runId: 'r_20260101000000_aaaaaa',
        projectId: 'p_aaaaaaaaaa',
        securevibeVersion: '0.1.0',
        knowledgeDir: join(REPO_ROOT, 'data', 'knowledge'),
        log: () => {},
      });

      expect(existsSync(appDir)).toBe(true);
      expect(existsSync(join(appDir, 'src', 'app.ts'))).toBe(true);
      expect(existsSync(join(appDir, '.env'))).toBe(true);
      expect(existsSync(join(appDir, 'securevibe.features.json'))).toBe(true);
      expect(existsSync(join(appDir, 'securevibe.design.json'))).toBe(true);
      expect(existsSync(join(appDir, 'securevibe.provenance.json'))).toBe(true);
      expect(existsSync(join(appDir, 'data', 'common-passwords.txt'))).toBe(true);

      // habitTracker has no auth/AI/uploads, so those feature dirs are removed.
      expect(existsSync(join(appDir, 'src', 'features', 'ai'))).toBe(false);
      expect(existsSync(join(appDir, 'src', 'features', 'uploads'))).toBe(false);

      expect(Object.keys(result.protectedFileHashes).length).toBeGreaterThan(0);
      expect(result.protectedFileHashes['src/app.ts']).toBeDefined();
      expect(result.manifest.name).toBe('secure-web-app');

      // The .env got the session policy and TLS mode this profile implies, not the template's raw placeholders.
      const { readFileSync } = await import('node:fs');
      const env = readFileSync(join(appDir, '.env'), 'utf8');
      expect(env).toMatch(/TLS_MODE=off/);
      expect(env).not.toMatch(/__generate_with_npm_run_setup__/);
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
    }
  }, 60_000);

  it('keeps the ai/uploads feature directories for a profile that turns them on', async () => {
    const projectDir = mkdtempSync(join(tmpdir(), 'securevibe-scaffold-'));
    try {
      const knowledge = loadKnowledge();
      const frameworks = loadFrameworks();
      const design = deriveDesign(teamInventory, { knowledge, frameworks });
      const flags = manifestFeatureFlags(design.buildSpec, teamInventory);
      expect(flags['uploads']).toBe(true);

      const appDir = join(projectDir, 'app');
      mkdirSync(projectDir, { recursive: true });
      await scaffoldApp({
        templateDir,
        projectDir,
        appDir,
        design,
        profile: teamInventory,
        buildSpec: design.buildSpec,
        settings: { model: 'claude-opus-5', generationEffort: 'high', reviewEffort: 'medium', defaultSpendingCapUsd: 15, maxFixRounds: 2, storeFullPrompts: true, aiEnabled: true, saveCredits: false },
        runId: 'r_20260101000000_bbbbbb',
        projectId: 'p_bbbbbbbbbb',
        securevibeVersion: '0.1.0',
        knowledgeDir: join(REPO_ROOT, 'data', 'knowledge'),
        log: () => {},
      });

      expect(existsSync(join(appDir, 'src', 'features', 'uploads'))).toBe(true);
      const hashes = computeProtectedFileHashes(appDir, JSON.parse((await import('node:fs')).readFileSync(join(appDir, 'securevibe.manifest.json'), 'utf8')));
      expect(hashes['package.json']).toBeDefined();
    } finally {
      rmSync(projectDir, { recursive: true, force: true });
    }
  }, 60_000);
});
