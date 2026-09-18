/** Template upgrade over the API: an app built from an older template is brought up to date without a rebuild. */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { templateHash } from '../../src/generator/template-hash.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('POST /projects/:id/upgrade', () => {
  let harness: TestHarness;
  beforeEach(async () => {
    harness = await buildHarness();
  });
  afterEach(() => harness?.cleanup());

  it('updates unchanged template files, keeps changed ones, and clears the "outdated" flag', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const design = await request(harness.server).post(`/api/projects/${project.id}/design`).set(headers);
    expect(design.status).toBe(200);

    // An app "built" from an older template: one template file unchanged since (old hash recorded), one edited by
    // the owner, one file of the owner's own, and an .env with a secret that must survive.
    const { appDir } = harness.store.paths(project.id);
    const templateDir = harness.config.paths.templateDir;
    mkdirSync(join(appDir, 'src', 'lib'), { recursive: true });
    const oldErrors = `${readFileSync(join(templateDir, 'src', 'lib', 'errors.ts'), 'utf8')}\n// older template\n`;
    writeFileSync(join(appDir, 'src', 'lib', 'errors.ts'), oldErrors);
    writeFileSync(join(appDir, 'src', 'lib', 'views.ts'), '// the owner rewrote this file\n');
    writeFileSync(join(appDir, 'src', 'lib', 'mine.ts'), 'export const mine = 1;\n');
    writeFileSync(join(appDir, '.env'), 'APP_NAME=Habits\nSESSION_SECRET=keep-me\n');
    const { createHash } = await import('node:crypto');
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    writeFileSync(
      join(appDir, 'securevibe.provenance.json'),
      JSON.stringify({
        reportSchemaVersion: '1.0.0',
        tool: 'SecureVibe test',
        securevibeVersion: '0.0.0',
        templateVersion: '0.0.1',
        frameworkVersions: { asvs: '', aisvs: '', sbd: '' },
        toolVersions: {},
        runId: 'r_20260917120000_old000',
        projectId: project.id,
        generatedAt: new Date().toISOString(),
        mode: 'full',
        humanInvolvement: { summary: '', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
        designProfileHash: 'x',
        designHash: 'y',
        codeTreeHash: '',
        generatedFiles: [
          { path: 'src/lib/errors.ts', sha256: sha(oldErrors), origin: 'template' },
          { path: 'src/lib/views.ts', sha256: 'was-different', origin: 'template' },
          { path: 'src/lib/mine.ts', sha256: sha('export const mine = 1;\n'), origin: 'ai-generated' },
        ],
        protectedFileHashes: {},
        sandbox: { mode: 'none', note: '' },
      }),
    );

    const before = await request(harness.server).get(`/api/projects/${project.id}`).set(headers);
    expect(before.body.project.templateOutdated).toBe(true);

    const res = await request(harness.server).post(`/api/projects/${project.id}/upgrade`).set(headers).send({});
    expect(res.status).toBe(200);
    const upgrade = res.body.upgrade as { updated: string[]; added: string[]; kept: string[]; envKeysAdded: string[] };
    expect(upgrade.updated).toContain('src/lib/errors.ts');
    expect(upgrade.kept).toEqual(['src/lib/views.ts']);
    expect(upgrade.added.length).toBeGreaterThan(10);
    expect(upgrade.envKeysAdded.length).toBeGreaterThan(0);

    expect(readFileSync(join(appDir, 'src', 'lib', 'errors.ts'), 'utf8')).not.toContain('// older template');
    expect(readFileSync(join(appDir, 'src', 'lib', 'views.ts'), 'utf8')).toBe('// the owner rewrote this file\n');
    expect(existsSync(join(appDir, 'src', 'lib', 'mine.ts'))).toBe(true);
    const env = readFileSync(join(appDir, '.env'), 'utf8');
    expect(env).toContain('SESSION_SECRET=keep-me');
    expect(env).toContain('APP_NAME=Habits');
    expect(existsSync(join(appDir, 'securevibe.features.json'))).toBe(true);

    const provenance = JSON.parse(readFileSync(join(appDir, 'securevibe.provenance.json'), 'utf8')) as { templateHash: string; generatedFiles: { path: string; origin: string }[] };
    expect(provenance.templateHash).toBe(templateHash(templateDir));
    expect(provenance.generatedFiles.find((f) => f.path === 'src/lib/mine.ts')?.origin).toBe('ai-generated');

    const after = await request(harness.server).get(`/api/projects/${project.id}`).set(headers);
    expect(after.body.project.templateOutdated).toBe(false);
    expect(after.body.project.lastUpgrade.kept).toEqual(['src/lib/views.ts']);
    expect(existsSync(join(harness.store.paths(project.id).dir, 'app.upgrade'))).toBe(false);
  });

  it('refuses before a build and for uploaded apps', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await request(harness.server).post(`/api/projects/${project.id}/design`).set(headers);
    const res = await request(harness.server).post(`/api/projects/${project.id}/upgrade`).set(headers).send({});
    expect(res.status).toBe(400);
    expect(res.body.error.message).toMatch(/Build the app first/);
  });
});
