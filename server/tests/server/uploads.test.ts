/** Checking an app the owner uploads: what is stored, what is refused, and how it is checked. */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const started: { job: Record<string, unknown> }[] = [];
vi.mock('../../src/pipeline/index.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/pipeline/index.js')>();
  return {
    ...actual,
    // No real worker in tests: record the job the route wrote and pretend a worker took it.
    spawnBuildWorker: (opts: { job: Record<string, unknown> }) => {
      started.push({ job: opts.job });
      return 4242;
    },
  };
});

const { skipReason, UPLOADED_SKIPPED_STAGES } = await import('../../src/api/uploads.js');
const { reviewScope, reviewTree } = await import('../../src/verification/index.js');
const { habitTracker } = await import('../fixtures/design/profiles.js');
const { buildHarness, signIn } = await import('./helpers.js');
type TestHarness = Awaited<ReturnType<typeof buildHarness>>;

describe('upload skip rules', () => {
  it('leaves out dependencies, build output, secrets and large files', () => {
    expect(skipReason('node_modules/express/index.js', 10)).toMatch(/dependencies/);
    expect(skipReason('web/dist/app.js', 10)).toMatch(/build output/);
    expect(skipReason('.env', 10)).toMatch(/secrets/);
    expect(skipReason('config/.env.production', 10)).toMatch(/secrets/);
    expect(skipReason('.env.example', 10)).toBeUndefined();
    expect(skipReason('certs/server.key', 10)).toMatch(/private key/);
    expect(skipReason('data/app.sqlite', 10)).toMatch(/database/);
    expect(skipReason('src/big.json', 3 * 1024 * 1024)).toMatch(/2 MB/);
    expect(skipReason('src/server.ts', 1000)).toBeUndefined();
  });
});

describe('checks left out for uploaded apps', () => {
  it('drops their findings and evidence, and says so', async () => {
    const { absorbScanResult } = await import('../../src/pipeline/stage-helpers.js');
    const stages: { id: string; status: string; summary: string }[] = [];
    const { mkdtempSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const logRoot = mkdtempSync(join(tmpdir(), 'securevibe-absorb-'));
    const ctx = {
      store: { projectPath: (...parts: string[]) => join(logRoot, ...parts) },
      project: { id: 'p_aaaaaaaaaa' },
      excludedChecks: new Set(['config.secrets-strength']),
      acc: { findings: [] as { ruleId: string }[], evidence: [] as { ref: string }[], coverage: [] as unknown[] },
      run: { id: 'r_20260917120000_abcdef', stages },
      bus: { stage: () => undefined, log: () => undefined },
      log: () => undefined,
    };
    const result = {
      status: 'failed',
      summary: '1 of 2 configuration checks did not pass.',
      findings: [{ ruleId: 'config.secrets-strength' }],
      evidence: [{ ref: 'config.secrets-strength' }, { ref: 'config.gitignore-covers-env' }],
      coverage: { tool: 'config', ran: true },
      details: {},
    };
    const stage = absorbScanResult(ctx as never, 'config', new Date(), result as never);
    expect(ctx.acc.findings).toEqual([]);
    expect(ctx.acc.evidence).toEqual([{ ref: 'config.gitignore-covers-env' }]);
    expect(stage.status).toBe('passed');
    expect(stage.summary).toMatch(/only apply to apps built by SecureVibe/);
  });
});

describe('uploading and checking an app', () => {
  let harness: TestHarness;
  let headers: Record<string, string>;

  beforeEach(async () => {
    started.length = 0;
    harness = await buildHarness();
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
  });
  afterEach(() => harness?.cleanup());

  const put = (id: string, path: string, body: string | Buffer) =>
    request(harness.server)
      .put(`/api/projects/${id}/upload/file?path=${encodeURIComponent(path)}`)
      .set(headers)
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from(body));

  async function uploadedProject(aiAssisted: boolean) {
    const res = await request(harness.server).post('/api/projects').set(headers).send({ name: 'My shop', mode: 'guided', uploaded: { aiAssisted } });
    expect(res.status).toBe(201);
    return res.body.project as { id: string };
  }

  it('stores the files safely and makes them the app folder', async () => {
    const { id } = await uploadedProject(true);
    expect((await put(id, 'src/app.js', 'x')).status).toBe(409); // not started yet
    expect((await request(harness.server).post(`/api/projects/${id}/upload/begin`).set(headers).send({})).status).toBe(200);

    expect((await put(id, 'src/app.js', 'console.log(1)')).body).toEqual({ stored: true });
    expect((await put(id, 'src/auth/login.js', 'export {}')).body).toEqual({ stored: true });
    expect((await put(id, 'src/empty.js', '')).body).toEqual({ stored: true });
    expect((await put(id, '.env', 'SECRET=1')).body).toEqual({ stored: false, reason: 'a secrets file (.env)' });
    expect((await put(id, 'node_modules/x/index.js', 'x')).body.stored).toBe(false);
    for (const bad of ['../escape.js', '/etc/passwd', 'a/../../b.js', 'a\\b.js', '']) {
      expect((await put(id, bad, 'x')).status, bad).toBe(400);
    }
    // Only raw bytes are accepted here; JSON goes nowhere.
    const json = await request(harness.server).put(`/api/projects/${id}/upload/file?path=a.js`).set(headers).send({ a: 1 });
    expect(json.status).toBe(400);

    const finish = await request(harness.server).post(`/api/projects/${id}/upload/finish`).set(headers).send({});
    expect(finish.status).toBe(200);
    expect(finish.body.project.origin).toMatchObject({ kind: 'uploaded', aiAssisted: true, upload: { files: 3, skipped: 2 } });
    const { appDir, dir } = harness.store.paths(id);
    expect(readFileSync(join(appDir, 'src', 'app.js'), 'utf8')).toBe('console.log(1)');
    expect(existsSync(join(appDir, '.env'))).toBe(false);
    expect(existsSync(join(dir, 'escape.js'))).toBe(false);
    expect(readdirSync(dir)).not.toContain('upload-staging');

    // The code-review scope for an uploaded app is the files whose names suggest security work.
    const scope = reviewScope(harness.store.mustGet(id), harness.store, harness.config)!;
    expect(reviewTree(scope).files).toEqual(['src/auth/login.js']);

    // A second upload keeps the first as app-v1.
    await request(harness.server).post(`/api/projects/${id}/upload/begin`).set(headers).send({});
    await put(id, 'index.js', 'v2');
    await request(harness.server).post(`/api/projects/${id}/upload/finish`).set(headers).send({});
    expect(existsSync(join(dir, 'app-v1', 'src', 'app.js'))).toBe(true);
    expect(existsSync(join(appDir, 'index.js'))).toBe(true);
  });

  it('refuses uploads for apps SecureVibe builds, and an empty upload', async () => {
    const built = harness.store.create({ name: 'Built', mode: 'guided', profile: habitTracker });
    expect((await request(harness.server).post(`/api/projects/${built.id}/upload/begin`).set(headers).send({})).status).toBe(400);
    const { id } = await uploadedProject(false);
    await request(harness.server).post(`/api/projects/${id}/upload/begin`).set(headers).send({});
    expect((await request(harness.server).post(`/api/projects/${id}/upload/finish`).set(headers).send({})).status).toBe(400);
  });

  it('only ever checks an uploaded app, without running its code, and never previews it', async () => {
    const { id } = await uploadedProject(false);
    await request(harness.server).post(`/api/projects/${id}/upload/begin`).set(headers).send({});
    await put(id, 'server.js', 'require("http")');
    const finished = await request(harness.server).post(`/api/projects/${id}/upload/finish`).set(headers).send({});
    expect(finished.status, JSON.stringify(finished.body)).toBe(200);
    harness.store.update(id, (p) => {
      p.profile = habitTracker;
    });
    const design = await request(harness.server).post(`/api/projects/${id}/design`).set(headers);
    expect(design.status).toBe(200);
    // Written without AI tools: the AI-assisted development rules do not apply.
    expect(design.body.design.applicability.appendixC.applicable).toEqual([]);

    const estimate = await request(harness.server).get(`/api/projects/${id}/estimate`).set(headers);
    const res = await request(harness.server)
      .post(`/api/projects/${id}/runs`)
      .set(headers)
      .send({ mode: 'full', approved: true, approvalCode: estimate.body.approvalCode, fixFindingIds: ['F-0001'] });
    expect(res.status, JSON.stringify(res.body)).toBe(202);
    const job = started[0]!.job;
    expect(job['mode']).toBe('verify-only');
    // The worker applies the uploaded-app rules (no code run, template-only checks left out) from this flag.
    expect(job['uploaded']).toBe(true);
    expect(job['fixFindingIds']).toBeUndefined();
    expect(UPLOADED_SKIPPED_STAGES.install).toMatch(/uploaded app/);

    expect((await request(harness.server).post(`/api/projects/${id}/preview`).set(headers).send({})).status).toBe(400);
    expect((await request(harness.server).get(`/api/projects/${id}/app/run-instructions`).set(headers)).status).toBe(404);
  });
});
