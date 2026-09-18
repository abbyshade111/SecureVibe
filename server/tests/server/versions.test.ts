/** Versions and "what changed" over the API: file changes with origins, secrets hidden, and the checks' movement. */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

function provenance(runId: string, files: { path: string; origin: string }[]): string {
  return JSON.stringify({
    reportSchemaVersion: '1.0.0',
    tool: 'SecureVibe test',
    securevibeVersion: '0.0.0',
    templateVersion: '0.1.0',
    frameworkVersions: { asvs: '', aisvs: '', sbd: '' },
    toolVersions: {},
    runId,
    projectId: 'p',
    generatedAt: '2026-09-17T10:00:00.000Z',
    mode: 'full',
    humanInvolvement: { summary: '', peerReviewDecisions: [], attestations: 0, humanCodeReview: false },
    designProfileHash: 'x',
    designHash: 'y',
    codeTreeHash: '',
    generatedFiles: files.map((f) => ({ ...f, sha256: 'n/a' })),
    protectedFileHashes: {},
    sandbox: { mode: 'none', note: '' },
  });
}

describe('app versions and diffs', () => {
  let harness: TestHarness;
  beforeEach(async () => {
    harness = await buildHarness();
  });
  afterEach(() => harness?.cleanup());

  it('lists versions, diffs files with their origins, hides secrets, and compares the checks', async () => {
    const { cookie } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie };
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const { dir, appDir } = harness.store.paths(project.id);
    const oldDir = join(dir, 'app-v1');
    for (const d of [join(appDir, 'src'), join(oldDir, 'src')]) mkdirSync(d, { recursive: true });

    writeFileSync(join(oldDir, 'src', 'a.ts'), 'const a = 1;\nconst b = 2;\n');
    writeFileSync(join(oldDir, 'src', 'gone.ts'), 'old\n');
    writeFileSync(join(oldDir, '.env'), 'SECRET=old\n');
    writeFileSync(join(oldDir, 'securevibe.provenance.json'), provenance('r_20260917100000_aaaaaa', [{ path: 'src/a.ts', origin: 'template' }, { path: 'src/gone.ts', origin: 'expanded' }]));

    writeFileSync(join(appDir, 'src', 'a.ts'), 'const a = 1;\nconst b = 3;\n');
    writeFileSync(join(appDir, 'src', 'new.ts'), 'new\n');
    writeFileSync(join(appDir, '.env'), 'SECRET=new\n');
    writeFileSync(join(appDir, 'securevibe.provenance.json'), provenance('r_20260917110000_bbbbbb', [{ path: 'src/a.ts', origin: 'ai-fixed' }, { path: 'src/new.ts', origin: 'ai-generated' }]));

    const runBase = { projectId: project.id, mode: 'full', stages: [], coverage: [], artifacts: [], fixRounds: 0, incomplete: false };
    const finding = (id: string, fingerprint: string, status: string) => ({
      id,
      fingerprint,
      source: 'sast',
      sourcesReporting: [],
      ruleId: 'sast.x',
      title: `Problem ${fingerprint}`,
      severity: 'high',
      confidence: 'high',
      cwe: [],
      description: '',
      impact: '',
      evidence: '',
      remediation: { summary: 'fix it' },
      verification: { howToConfirmFixed: 'run the check again' },
      mappings: {},
      status,
      whoCanFix: 'developer',
      introducedBy: 'unknown',
    });
    harness.store.writeRunSync({
      ...runBase,
      id: 'r_20260917100000_aaaaaa',
      startedAt: '2026-09-17T10:00:00.000Z',
      finishedAt: '2026-09-17T10:05:00.000Z',
      status: 'succeeded',
      findings: [finding('F-0001', 'fp-old', 'open'), finding('F-0002', 'fp-both', 'open')],
    } as never);
    harness.store.writeRunSync({
      ...runBase,
      id: 'r_20260917110000_bbbbbb',
      startedAt: '2026-09-17T11:00:00.000Z',
      finishedAt: '2026-09-17T11:05:00.000Z',
      status: 'succeeded',
      findings: [finding('F-0001', 'fp-both', 'open'), finding('F-0002', 'fp-new', 'open'), finding('F-0003', 'fp-fixed', 'fixed')],
    } as never);
    harness.store.update(project.id, (p) => {
      p.lastRunId = 'r_20260917110000_bbbbbb';
      p.appVersion = 1;
    });

    const versions = await request(harness.server).get(`/api/projects/${project.id}/versions`).set(headers);
    expect(versions.status).toBe(200);
    expect(versions.body.versions.map((v: { id: string }) => v.id)).toEqual(['current', 'v1']);
    expect(versions.body.versions[0].runId).toBe('r_20260917110000_bbbbbb');
    expect(versions.body.versions[1].builtAt).toBe('2026-09-17T10:05:00.000Z');

    const diff = await request(harness.server).get(`/api/projects/${project.id}/diff`).set(headers);
    expect(diff.status).toBe(200);
    expect(diff.body.from.id).toBe('v1');
    expect(diff.body.to.id).toBe('current');
    const byPath = Object.fromEntries((diff.body.files as { path: string }[]).map((f) => [f.path, f]));
    expect(byPath['src/a.ts']).toMatchObject({ kind: 'changed', origin: 'ai-fixed', linesAdded: 1, linesRemoved: 1 });
    expect(byPath['src/new.ts']).toMatchObject({ kind: 'added', origin: 'ai-generated' });
    expect(byPath['src/gone.ts']).toMatchObject({ kind: 'removed', origin: 'expanded' });
    expect(byPath['.env']).toMatchObject({ kind: 'changed', secret: true, linesAdded: 0 });
    expect(byPath['securevibe.provenance.json']).toBeUndefined();

    expect(diff.body.results.findingsNew.map((f: { fingerprint: string }) => f.fingerprint)).toEqual(['fp-new']);
    expect(diff.body.results.findingsResolved.map((f: { fingerprint: string }) => f.fingerprint)).toEqual(['fp-old']);
    expect(diff.body.results.findingsStillOpen).toBe(1);

    const file = await request(harness.server).get(`/api/projects/${project.id}/diff/file?from=v1&to=current&path=src/a.ts`).set(headers);
    expect(file.status).toBe(200);
    expect(file.body.unified).toContain('-const b = 2;\n+const b = 3;');

    const secret = await request(harness.server).get(`/api/projects/${project.id}/diff/file?from=v1&to=current&path=.env`).set(headers);
    expect(secret.body.unified).not.toContain('SECRET=');

    const outside = await request(harness.server).get(`/api/projects/${project.id}/diff/file?from=v1&to=current&path=../project.json`).set(headers);
    expect(outside.status).toBeGreaterThanOrEqual(400);
    const missing = await request(harness.server).get(`/api/projects/${project.id}/diff?from=v9&to=current`).set(headers);
    expect(missing.status).toBe(404);
  });
});
