/**
 * Build approval (AISVS C9.2.1, Appendix C AC.4/AC.8.1): a build starts only with the one-time code issued when the
 * owner's estimate was shown, and refused requests are logged at the default log level (ASVS V16.3).
 */
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

const { BuildApprovals, APPROVAL_TTL_MS } = await import('../../src/api/approvals.js');
const { habitTracker } = await import('../fixtures/design/profiles.js');
const { buildHarness, signIn } = await import('./helpers.js');
type TestHarness = Awaited<ReturnType<typeof buildHarness>>;

describe('BuildApprovals', () => {
  const base = { projectId: 'p_aaaaaaaaaa', sessionId: 'session-1', designHash: 'h1', estimateUsdHigh: 3 };

  it('grants an approval once, for the session, app and design it was issued for', () => {
    const approvals = new BuildApprovals();
    const code = approvals.issue(base);
    const granted = approvals.consume(code, 'p_aaaaaaaaaa', 'session-1', 'h1');
    expect(typeof granted).toBe('object');
    if (typeof granted === 'object') {
      expect(granted.approvedBy).toMatch(/^owner \(signed-in session [0-9a-f]{12}\)$/);
      expect(granted.approvedBy).not.toContain('session-1');
      expect(granted.estimateUsdHigh).toBe(3);
    }
    expect(approvals.consume(code, 'p_aaaaaaaaaa', 'session-1', 'h1')).toBe('missing');
  });

  it('refuses another session without using up the code', () => {
    const approvals = new BuildApprovals();
    const code = approvals.issue(base);
    expect(approvals.consume(code, 'p_aaaaaaaaaa', 'session-2', 'h1')).toBe('wrong-session');
    expect(approvals.consume(code, 'p_bbbbbbbbbb', 'session-1', 'h1')).toBe('wrong-project');
    expect(typeof approvals.consume(code, 'p_aaaaaaaaaa', 'session-1', 'h1')).toBe('object');
  });

  it('refuses a changed design and an old approval', () => {
    let now = 1_000_000;
    const approvals = new BuildApprovals(() => now);
    expect(approvals.consume(approvals.issue(base), 'p_aaaaaaaaaa', 'session-1', 'h2')).toBe('design-changed');
    const code = approvals.issue(base);
    now += APPROVAL_TTL_MS + 1;
    expect(approvals.consume(code, 'p_aaaaaaaaaa', 'session-1', 'h1')).toBe('expired');
  });
});

describe('starting a build over the API', () => {
  let harness: TestHarness;
  const logLines: Record<string, unknown>[] = [];

  beforeEach(async () => {
    started.length = 0;
    logLines.length = 0;
    harness = await buildHarness({ logLines });
  });
  afterEach(() => harness?.cleanup());

  async function designedProject(headers: Record<string, string>) {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const design = await request(harness.server).post(`/api/projects/${project.id}/design`).set(headers);
    expect(design.status).toBe(200);
    return project;
  }

  it('starts only with the code from the estimate, and records the owner approval', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    const project = await designedProject(headers);

    const noCode = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true });
    expect(noCode.status).toBe(400);
    const madeUp = await request(harness.server)
      .post(`/api/projects/${project.id}/runs`)
      .set(headers)
      .send({ mode: 'full', approved: true, approvalCode: 'x'.repeat(32) });
    expect(madeUp.status).toBe(403);
    expect(started).toHaveLength(0);

    const estimate = await request(harness.server).get(`/api/projects/${project.id}/estimate`).set(headers);
    expect(estimate.status).toBe(200);
    const approvalCode = estimate.body.approvalCode as string;
    const ok = await request(harness.server)
      .post(`/api/projects/${project.id}/runs`)
      .set(headers)
      .send({ mode: 'full', approved: true, approvalCode, spendingCapUsd: 7 });
    expect(ok.status).toBe(202);
    expect(started).toHaveLength(1);
    const approval = started[0]!.job['approval'] as Record<string, unknown>;
    expect(approval['approvedBy']).toMatch(/^owner \(signed-in session [0-9a-f]{12}\)$/);
    expect(approval['spendingCapUsd']).toBe(7);
    // The run record exists before the worker starts, so the page can follow it straight away.
    expect(harness.store.findRun(ok.body.run.id as string)?.status).toBe('running');
    expect(harness.store.mustGet(project.id).status).toBe('building');

    // The code works once.
    const reused = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true, approvalCode });
    expect(reused.status).toBe(403);
    expect(started).toHaveLength(1);

    expect(logLines.some((l) => l['event'] === 'build.approved' && l['projectId'] === project.id && l['level'] === 30)).toBe(true);
    expect(logLines.some((l) => l['event'] === 'build.approval_refused' && l['reason'] === 'missing')).toBe(true);
    // The approval code itself never reaches the log.
    expect(JSON.stringify(logLines)).not.toContain(approvalCode);
  });

  it('runs a free re-check without AI even when AI is on, and leaves the self-assessment to the command line', async () => {
    harness.cleanup();
    const { ScriptedProvider } = await import('../../src/llm/scripted.js');
    const { FIXTURE_DIR } = await import('../llm/helpers.js');
    harness = await buildHarness({ logLines, provider: new ScriptedProvider({ dir: FIXTURE_DIR, scenario: 'peer-review' }) });
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    const project = await designedProject(headers);
    const code = async () => (await request(harness.server).get(`/api/projects/${project.id}/estimate`).set(headers)).body.approvalCode as string;

    const full = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true, approvalCode: await code(), withoutAi: true });
    expect(full.status).toBe(400);
    const res = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'verify-only', approved: true, approvalCode: await code(), withoutAi: true });
    expect(res.status).toBe(202);
    expect(started.at(-1)!.job).toMatchObject({ withoutAi: true, mode: 'verify-only' });

    const self = harness.store.create({ name: 'SecureVibe self-assessment', mode: 'quick', profile: habitTracker });
    const refused = await request(harness.server).post(`/api/projects/${self.id}/runs`).set(headers).send({ mode: 'verify-only', approved: true, approvalCode: 'x'.repeat(32), withoutAi: true });
    expect(refused.status).toBe(400);
  });

  it('refuses an approval given for a design that has since changed', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    const project = await designedProject(headers);
    const estimate = await request(harness.server).get(`/api/projects/${project.id}/estimate`).set(headers);
    harness.store.update(project.id, (p) => {
      p.design = { ...p.design!, profileHash: 'changed' };
    });
    const res = await request(harness.server)
      .post(`/api/projects/${project.id}/runs`)
      .set(headers)
      .send({ mode: 'full', approved: true, approvalCode: estimate.body.approvalCode });
    expect(res.status).toBe(403);
    expect(res.body.error.message).toMatch(/design changed/);
    expect(started).toHaveLength(0);
  });
});

describe('logging refused requests', () => {
  let harness: TestHarness;
  const logLines: Record<string, unknown>[] = [];

  beforeEach(async () => {
    logLines.length = 0;
    harness = await buildHarness({ logLines });
  });
  afterEach(() => harness?.cleanup());

  const events = () => logLines.filter((l) => typeof l['event'] === 'string').map((l) => ({ event: l['event'], level: l['level'] }));

  it('records sign-in, missing sessions, CSRF and cross-site refusals at the default level', async () => {
    await request(harness.server).get('/auth/token?t=wrong').set('Host', '127.0.0.1');
    await request(harness.server).get('/api/projects').set('Host', '127.0.0.1');
    const { cookie } = await signIn(harness);
    await request(harness.server).post('/api/projects').set({ Host: '127.0.0.1', Cookie: cookie }).send({ name: 'x', mode: 'guided' });
    await request(harness.server)
      .post('/api/projects')
      .set({ Host: '127.0.0.1', Cookie: cookie, Origin: 'https://evil.example' })
      .send({ name: 'x', mode: 'guided' });

    expect(events()).toEqual(
      expect.arrayContaining([
        { event: 'auth.token_rejected', level: 40 },
        { event: 'auth.denied', level: 40 },
        { event: 'auth.token_accepted', level: 30 },
        { event: 'csrf.rejected', level: 40 },
        { event: 'origin.blocked', level: 40 },
      ]),
    );
    // Neither the startup token nor the session cookie is written to the log.
    const text = JSON.stringify(logLines);
    expect(text).not.toContain(harness.sessions.startupToken);
    expect(text).not.toContain(cookie.split(';')[0]!.split('=')[1]!);
  });

  it('records rejected input at info and keeps missing pages at debug', async () => {
    const { cookie, csrfToken } = await signIn(harness);
    const headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
    await request(harness.server).post('/api/projects').set(headers).send({ name: '', mode: 'nonsense' });
    await request(harness.server).get('/api/projects/p_zzzzzzzzzz').set(headers);
    expect(events()).toContainEqual({ event: 'validation.rejected', level: 30 });
    expect(events().some((e) => e.event === 'request.not_found')).toBe(false);
  });
});
