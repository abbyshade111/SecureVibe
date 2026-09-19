/**
 * `GET /api/security`: every app at once. The tests are about the three ways this view could lie — counting a
 * partial run, showing a zero for an app nobody has checked, and adding one app's findings to another's.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import type { Finding } from '@shared/findings.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { RERUNNABLE_CHECKS } from '@shared/pipeline.js';
import { clinicBookings, habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

/** A finding with just the fields this view reads. */
function finding(id: string, severity: Finding['severity'], whoCanFix: Finding['whoCanFix'] = 'developer'): Finding {
  return {
    id,
    fingerprint: `fp-${id}`,
    source: 'sast',
    sourcesReporting: ['sast'],
    ruleId: 'sast.example',
    title: `Example ${id}`,
    severity,
    confidence: 'high',
    cwe: [],
    description: 'An example finding.',
    impact: 'It would matter.',
    evidence: 'The scanner saw something.',
    remediation: { summary: 'Fix it.', steps: [], references: [] },
    mappings: { asvs: [], aisvs: [], sbd: [] },
    status: 'open',
    whoCanFix,
    introducedBy: 'unknown',
  } as unknown as Finding;
}

function run(projectId: string, id: string, opts: { partial?: boolean; findings?: Finding[]; finishedAt?: string } = {}): PipelineRun {
  return {
    projectId,
    id,
    mode: 'verify-only' as const,
    status: 'succeeded' as const,
    startedAt: '2026-09-01T10:00:00.000Z',
    finishedAt: opts.finishedAt ?? '2026-09-01T10:05:00.000Z',
    findings: opts.findings ?? [],
    coverage: [],
    ...(opts.partial ? { partial: true, partialChecks: ['sast'] } : {}),
    stages: RERUNNABLE_CHECKS.map((stage) => ({ id: stage, status: 'passed', summary: `${stage} ran.`, round: 0, finishedAt: '2026-09-01T10:04:00.000Z' })),
  } as unknown as PipelineRun;
}

describe('security across every app', () => {
  let harness: TestHarness;
  let headers: Record<string, string>;

  beforeEach(async () => {
    harness = await buildHarness();
    const { cookie, csrfToken } = await signIn(harness);
    headers = { Host: '127.0.0.1', Cookie: cookie, 'X-CSRF-Token': csrfToken, Origin: 'http://127.0.0.1:4173' };
  });
  afterEach(() => harness?.cleanup());

  const get = async () => {
    const res = await request(harness.server).get('/api/security').set(headers);
    expect(res.status).toBe(200);
    return res.body as {
      apps: {
        projectId: string;
        name: string;
        exposure: string;
        open?: Record<string, number>;
        noCounts?: string;
        decided: { accepted: number; falsePositive: number };
        whoCanFix: Record<string, number>;
        since: { partialChecks: number; rebuilt: boolean; answersChanged: boolean };
        lastFullCheck?: { runId: string };
      }[];
      appsNeedingAttention: number;
      appsNeverFullyChecked: number;
    };
  };

  it('says an app has never been checked instead of showing it as clean', async () => {
    harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const body = await get();
    expect(body.apps).toHaveLength(1);
    expect(body.apps[0]!.noCounts).toBe('never-built');
    // The difference that matters: no numbers at all, rather than zeros that read as "nothing wrong".
    expect(body.apps[0]!.open).toBeUndefined();
    expect(body.appsNeverFullyChecked).toBe(1);
    expect(body.appsNeedingAttention).toBe(1);
  });

  it('counts only a run that ran every check, and says how many single checks came after it', async () => {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await harness.store.writeRun(run(project.id, 'r_20260901100000_aafull', { findings: [finding('a', 'high'), finding('b', 'low')] }));
    // A single-check re-run afterwards holds findings from that check alone. Counting it would show the app
    // improving because less was looked at, which is the opposite of what happened.
    await harness.store.writeRun(run(project.id, 'r_20260902100000_bbpart', { partial: true, findings: [], finishedAt: '2026-09-02T10:01:00.000Z' }));
    harness.store.update(project.id, (p) => {
      p.lastRunId = 'r_20260902100000_bbpart';
    });

    const body = await get();
    const app = body.apps[0]!;
    expect(app.lastFullCheck?.runId).toBe('r_20260901100000_aafull');
    expect(app.open).toEqual({ high: 1, low: 1 });
    expect(app.since.partialChecks).toBe(1);
  });

  it('respects what a person has already decided about a finding', async () => {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await harness.store.writeRun(run(project.id, 'r_20260901100000_aafull', { findings: [finding('a', 'high'), finding('b', 'high'), finding('c', 'medium')] }));
    harness.store.setFindingDecision(project.id, { fingerprint: 'fp-a', status: 'accepted', triage: { reason: 'Only on my laptop.', by: 'owner', at: '2026-09-02T10:00:00.000Z' } });
    harness.store.setFindingDecision(project.id, { fingerprint: 'fp-b', status: 'false-positive', triage: { reason: 'The scanner misread it.', by: 'owner', at: '2026-09-02T10:00:00.000Z' } });

    const body = await get();
    const app = body.apps[0]!;
    // Neither is open any more, and the two decisions are reported apart, because "I accept this risk" and "this
    // was never a problem" mean opposite things.
    expect(app.open).toEqual({ medium: 1 });
    expect(app.decided).toEqual({ accepted: 1, falsePositive: 1 });
    expect(app.whoCanFix).toEqual({ developer: 1 });
  });

  it('keeps every app separate, and counts apps rather than findings across them', async () => {
    const laptop = harness.store.create({ name: 'Notes on my laptop', mode: 'guided', profile: habitTracker });
    const clinic = harness.store.create({ name: 'Clinic bookings', mode: 'guided', profile: clinicBookings });
    await harness.store.writeRun(run(laptop.id, 'r_20260901100000_aalapt', { findings: [finding('l1', 'low'), finding('l2', 'low')] }));
    await harness.store.writeRun(run(clinic.id, 'r_20260901100000_bbclin', { findings: [finding('c1', 'critical')] }));

    const body = await get();
    const byName = new Map(body.apps.map((a) => [a.name, a]));
    expect(byName.get('Notes on my laptop')!.open).toEqual({ low: 2 });
    expect(byName.get('Clinic bookings')!.open).toEqual({ critical: 1 });
    // Nothing anywhere in the response adds the two together: a local-only note-taker's two low findings and a
    // clinic's one critical one are not three of anything.
    expect(JSON.stringify(body)).not.toContain('"total"');
    expect(body.appsNeedingAttention).toBe(1);
    // The app with something serious open comes first, whatever order the projects were made in.
    expect(body.apps[0]!.name).toBe('Clinic bookings');
    // And the thing that makes the two incomparable is on each row.
    expect(byName.get('Notes on my laptop')!.exposure).toBe('local-only');
  });

  it('says when the app was rebuilt or the answers changed after the check it is reporting', async () => {
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await harness.store.writeRun(run(project.id, 'r_20260901100000_aafull', { findings: [finding('a', 'medium')] }));
    await harness.store.writeRun(run(project.id, 'r_20260903100000_ccbuil', { finishedAt: '2026-09-03T10:05:00.000Z' }));
    harness.store.update(project.id, (p) => {
      p.lastRunId = 'r_20260903100000_ccbuil';
      p.designStale = true;
    });

    const body = await get();
    const app = body.apps[0]!;
    // The newer full run is the one reported, and the changed answers are flagged so nobody reads it as current.
    expect(app.lastFullCheck?.runId).toBe('r_20260903100000_ccbuil');
    expect(app.since.answersChanged).toBe(true);
  });

  it('serves the findings of the run the numbers came from, not just the latest run', async () => {
    // The across-apps page counts from the last run that ran every check. Its drill-down has to read the same run:
    // when a single-check re-run is the latest, reading that instead showed "1 critical" above an empty list, which
    // is the same number-and-sentence disagreement this whole view exists to avoid. Found by looking at the page.
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await harness.store.writeRun(run(project.id, 'r_20260901100000_aafull', { findings: [finding('a', 'critical')] }));
    await harness.store.writeRun(run(project.id, 'r_20260902100000_bbpart', { partial: true, findings: [], finishedAt: '2026-09-02T10:01:00.000Z' }));
    harness.store.update(project.id, (p) => {
      p.lastRunId = 'r_20260902100000_bbpart';
    });

    // The latest run is the partial one, and on its own terms it really did find nothing.
    const latest = await request(harness.server).get(`/api/projects/${project.id}/findings`).set(headers);
    expect(latest.status).toBe(200);
    expect(latest.body.findings).toEqual([]);

    // Asked for the full run, the critical finding is there — the one the page counted.
    const full = await request(harness.server).get(`/api/projects/${project.id}/findings?run=r_20260901100000_aafull`).set(headers);
    expect(full.status).toBe(200);
    expect(full.body.findings.map((f: { severity: string }) => f.severity)).toEqual(['critical']);

    // A run id that is not one, and one that belongs to no run, are both refused rather than read as a path.
    expect((await request(harness.server).get(`/api/projects/${project.id}/findings?run=../../etc/passwd`).set(headers)).status).toBe(400);
    expect((await request(harness.server).get(`/api/projects/${project.id}/findings?run=r_20260101000000_zzzzzz`).set(headers)).status).toBe(404);
  });

  it('records a decision about a finding from an earlier run, rather than refusing it', async () => {
    // The page showed the finding as decided and the server had refused it, because the decision route only looked
    // in the latest run — the partial one. A person could mark something a false positive and have nothing saved.
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    await harness.store.writeRun(run(project.id, 'r_20260901100000_aafull', { findings: [finding('a', 'critical')] }));
    await harness.store.writeRun(run(project.id, 'r_20260902100000_bbpart', { partial: true, findings: [], finishedAt: '2026-09-02T10:01:00.000Z' }));
    harness.store.update(project.id, (p) => {
      p.lastRunId = 'r_20260902100000_bbpart';
    });

    // Without the run, the finding is not in the latest run and the refusal is honest.
    const blind = await request(harness.server)
      .post(`/api/projects/${project.id}/findings/a/decision`)
      .set(headers)
      .send({ status: 'false-positive', triage: { reason: 'The scanner misread the route registry.' } });
    expect(blind.status).toBe(404);

    const saved = await request(harness.server)
      .post(`/api/projects/${project.id}/findings/a/decision?run=r_20260901100000_aafull`)
      .set(headers)
      .send({ status: 'false-positive', triage: { reason: 'The scanner misread the route registry.' } });
    expect(saved.status).toBe(204);

    // And the view stops counting it, without moving it to "accepted", which would mean something else entirely.
    const body = await get();
    expect(body.apps[0]!.open).toEqual({});
    expect(body.apps[0]!.decided).toEqual({ accepted: 0, falsePositive: 1 });
  });
});
