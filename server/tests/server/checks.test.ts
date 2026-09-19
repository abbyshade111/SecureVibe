/**
 * The Security page's data: which checks can be run on their own, what each of them last said, and the refusal to
 * run a step on its own that would cost money or decide compliance from a fraction of the evidence.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import type { PipelineRun } from '@shared/pipeline.js';
import { RERUNNABLE_CHECKS } from '@shared/pipeline.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('the checks a person can run again', () => {
  let harness: TestHarness;
  let projectId: string;
  let headers: Record<string, string>;

  beforeEach(async () => {
    harness = await buildHarness();
    projectId = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker }).id;
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken, Origin: 'http://127.0.0.1:4173' };
  });
  afterEach(() => harness?.cleanup());

  it('lists every check, and says plainly that none has run yet', async () => {
    const res = await request(harness.server).get(`/api/projects/${projectId}/checks`).set(headers);
    expect(res.status).toBe(200);
    expect(res.body.checks.map((c: { id: string }) => c.id)).toEqual([...RERUNNABLE_CHECKS]);
    expect(res.body.checks.every((c: { status: string }) => c.status === 'never-run')).toBe(true);
    expect(res.body.lastFullCheck).toBeUndefined();
    expect(res.body.running).toBe(false);
    // Neither the step that spends money nor the one that decides compliance is offered on its own.
    expect(res.body.checks.map((c: { id: string }) => c.id)).not.toContain('ai-review');
    expect(res.body.checks.map((c: { id: string }) => c.id)).not.toContain('compliance');
  });

  it('does not lock the page for ever because a run died without saying so', async () => {
    // A worker that is killed — the machine sleeps, SecureVibe is stopped mid-check, the process dies — never
    // writes its run again, so it says "running" for good. The page disables every button while something is
    // running, so believing that status leaves an owner with a page of dead buttons and no way back. An owner
    // reported exactly that.
    const stuck = {
      projectId,
      id: 'r_20260919090000_cccccc',
      mode: 'verify-only' as const,
      status: 'running' as const,
      startedAt: '2026-09-19T09:00:00.000Z',
      findings: [],
      coverage: [],
      stages: [{ id: 'sast', status: 'passed', summary: 'Nothing found in the code.', round: 0, finishedAt: '2026-09-19T09:01:00.000Z' }],
    } as unknown as PipelineRun;
    await harness.store.writeRun(stuck);

    const res = await request(harness.server).get(`/api/projects/${projectId}/checks`).set(headers);
    expect(res.status).toBe(200);
    // No worker was ever recorded for it, so nothing is executing and the buttons stay usable.
    expect(res.body.running).toBe(false);
    // What it did manage to finish is still worth showing.
    expect(res.body.checks.find((c: { id: string }) => c.id === 'sast').status).toBe('passed');
  });

  it('keeps the result of the run that really made a check, not the run that left it out', async () => {
    const base = {
      projectId,
      mode: 'verify-only' as const,
      status: 'succeeded' as const,
      startedAt: '2026-09-17T10:00:00.000Z',
      finishedAt: '2026-09-17T10:05:00.000Z',
      findings: [],
      coverage: [],
      stages: [],
    };
    const full = {
      ...base,
      id: 'r_20260917100000_aaaaaa',
      stages: [
        { id: 'sast', status: 'passed', summary: 'Nothing found in the code.', round: 0, finishedAt: '2026-09-17T10:02:00.000Z' },
        { id: 'deps', status: 'warning', summary: 'One package is out of date.', round: 0, finishedAt: '2026-09-17T10:03:00.000Z' },
      ],
    } as unknown as PipelineRun;
    const partial = {
      ...base,
      id: 'r_20260918100000_bbbbbb',
      startedAt: '2026-09-18T10:00:00.000Z',
      finishedAt: '2026-09-18T10:01:00.000Z',
      partial: true,
      partialChecks: ['sast'],
      stages: [
        { id: 'sast', status: 'failed', summary: 'Two things to look at.', round: 0, finishedAt: '2026-09-18T10:01:00.000Z' },
        { id: 'deps', status: 'skipped', summary: 'You asked for some of the checks only.', round: 0 },
      ],
    } as unknown as PipelineRun;
    await harness.store.writeRun(full);
    await harness.store.writeRun(partial);

    const res = await request(harness.server).get(`/api/projects/${projectId}/checks`).set(headers);
    const byId = Object.fromEntries((res.body.checks as { id: string; status: string; runId?: string }[]).map((c) => [c.id, c]));
    // The newer, partial run is where the code review stands; the dependency check keeps the older, real result.
    expect(byId['sast']).toMatchObject({ status: 'failed', runId: partial.id });
    expect(byId['deps']).toMatchObject({ status: 'warning', runId: full.id });
    expect(byId['dast']!.status).toBe('never-run');
    // The reports still come from the last run that checked everything.
    expect(res.body.lastFullCheck).toMatchObject({ runId: full.id, status: 'succeeded' });
  });

  it('refuses to run a step on its own that is not one of these checks', async () => {
    const res = await request(harness.server)
      .post(`/api/projects/${projectId}/runs`)
      .set(headers)
      .send({ mode: 'verify-only', approved: true, approvalCode: 'x'.repeat(24), withoutAi: true, checks: ['ai-review'] });
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(res.body)).toMatch(/not checks that can be run on their own/i);
  });
});

describe('continuing a build that stopped', () => {
  let harness: TestHarness;
  let projectId: string;
  let headers: Record<string, string>;

  beforeEach(async () => {
    harness = await buildHarness();
    projectId = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker }).id;
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken, Origin: 'http://127.0.0.1:4173' };
    // A build needs a frozen design; these tests are about what happens after that.
    const design = await request(harness.server).post(`/api/projects/${projectId}/design`).set(headers);
    expect(design.status).toBe(200);
  });
  afterEach(() => harness?.cleanup());

  async function ask(resumeFromRunId: string) {
    return request(harness.server)
      .post(`/api/projects/${projectId}/runs`)
      .set(headers)
      .send({ mode: 'full', approved: true, approvalCode: 'x'.repeat(24), resumeFromRunId });
  }

  it('refuses to continue a build that does not exist, or one that finished', async () => {
    const missing = await ask('r_20260918120000_aaaaaa');
    expect(missing.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(missing.body)).toMatch(/nothing to continue/i);

    await harness.store.writeRun({
      id: 'r_20260918130000_bbbbbb',
      projectId,
      mode: 'full',
      status: 'succeeded',
      startedAt: '2026-09-18T13:00:00.000Z',
      stages: [],
      findings: [],
      coverage: [],
    } as never);
    const finished = await ask('r_20260918130000_bbbbbb');
    expect(finished.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(finished.body)).toMatch(/finished/i);
  });

  it('refuses when there is no app folder left to continue from', async () => {
    await harness.store.writeRun({
      id: 'r_20260918140000_cccccc',
      projectId,
      mode: 'full',
      status: 'failed',
      startedAt: '2026-09-18T14:00:00.000Z',
      stages: [{ id: 'generate', status: 'failed', summary: 'stopped', round: 0 }],
      findings: [],
      coverage: [],
    } as never);
    const res = await ask('r_20260918140000_cccccc');
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(JSON.stringify(res.body)).toMatch(/not there any more|built from the start/i);
  });
});
