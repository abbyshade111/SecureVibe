/** The plan over the API: prepared with AI, approved by the owner, required for a build that writes with AI. */
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

const { ScriptedProvider } = await import('../../src/llm/scripted.js');
const { FIXTURE_DIR } = await import('../llm/helpers.js');
const { habitTracker } = await import('../fixtures/design/profiles.js');
const { buildHarness, signIn } = await import('./helpers.js');
type TestHarness = Awaited<ReturnType<typeof buildHarness>>;

describe('the build plan over the API', () => {
  let harness: TestHarness;
  let headers: Record<string, string>;

  beforeEach(async () => {
    started.length = 0;
    harness = await buildHarness({ provider: new ScriptedProvider({ dir: FIXTURE_DIR, scenario: 'plan' }) });
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken };
  });
  afterEach(() => harness?.cleanup());

  async function designed() {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    expect((await request(harness.server).post(`/api/projects/${project.id}/design`).set(headers)).status).toBe(200);
    return project;
  }
  const code = async (id: string) => (await request(harness.server).get(`/api/projects/${id}/estimate`).set(headers)).body.approvalCode as string;

  it('will not write with AI until a plan for this design is approved, then passes the plan to the build', async () => {
    const project = await designed();
    const noPlan = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true, approvalCode: await code(project.id) });
    expect(noPlan.status).toBe(400);
    expect(noPlan.body.error.message).toMatch(/Approve the build plan first/);

    const planned = await request(harness.server).post(`/api/projects/${project.id}/plan`).set(headers).send({});
    expect(planned.status).toBe(200);
    const features = planned.body.plan.features as { id: string }[];
    expect(features).toHaveLength(3);
    // Prepared but not yet approved: still no build.
    expect((await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true, approvalCode: await code(project.id) })).status).toBe(400);

    const approved = await request(harness.server).post(`/api/projects/${project.id}/plan/approve`).set(headers).send({ featureIds: [features[0]!.id, features[1]!.id] });
    expect(approved.status).toBe(200);
    expect(approved.body.plan.features.map((f: { wanted: boolean }) => f.wanted)).toEqual([true, true, false]);

    const run = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true, approvalCode: await code(project.id) });
    expect(run.status).toBe(202);
    const plan = started[0]!.job['plan'] as { features: { wanted: boolean }[]; approvedAt?: string };
    expect(plan.approvedAt).toBeDefined();
    expect(plan.features.filter((f) => f.wanted)).toHaveLength(2);
  });

  it('needs no plan for a check-only run or a build without AI', async () => {
    const project = await designed();
    const check = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'verify-only', approved: true, approvalCode: await code(project.id) });
    expect(check.status).toBe(202);
    const free = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'verify-only', approved: true, approvalCode: await code(project.id), withoutAi: true });
    expect(free.status).toBe(202);
    expect(started.every((s) => s.job['plan'] === undefined)).toBe(true);
  });

  it('a plan for an earlier design does not count', async () => {
    const project = await designed();
    await request(harness.server).post(`/api/projects/${project.id}/plan`).set(headers).send({});
    const first = (await request(harness.server).post(`/api/projects/${project.id}/plan/approve`).set(headers).send({ featureIds: ['PF-01'] })).body.plan;
    // The answers change, so the design changes: the old plan no longer applies.
    await request(harness.server).put(`/api/projects/${project.id}/profile`).set(headers).send({ profile: { deployment: { businessImpact: 'high' } } });
    await request(harness.server).post(`/api/projects/${project.id}/design`).set(headers);
    const res = await request(harness.server).post(`/api/projects/${project.id}/runs`).set(headers).send({ mode: 'full', approved: true, approvalCode: await code(project.id) });
    expect(res.status).toBe(400);
    expect((await request(harness.server).post(`/api/projects/${project.id}/plan/approve`).set(headers).send({ featureIds: ['PF-01'] })).status).toBe(400);
    expect(first.approvedAt).toBeDefined();
  });
});
