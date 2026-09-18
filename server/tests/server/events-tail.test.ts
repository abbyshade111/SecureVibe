/**
 * A build that runs in a worker process writes its progress to `events.jsonl`; the server streams that file to the
 * page — including after a restart, when the server has no bus for the run any more.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { EVENTS_FILE } from '../../src/pipeline/job.js';
import { habitTracker } from '../fixtures/design/profiles.js';
import { buildHarness, signIn, type TestHarness } from './helpers.js';

describe('event stream for a worker-run build', () => {
  let harness: TestHarness;
  beforeEach(async () => {
    harness = await buildHarness();
  });
  afterEach(() => harness?.cleanup());

  it('replays the events file of a finished run and then closes the stream', async () => {
    const { cookie } = await signIn(harness);
    const project = harness.store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const runId = 'r_20260917120000_cccccc';
    harness.store.writeRunSync({ id: runId, projectId: project.id, mode: 'verify-only', startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), status: 'succeeded', stages: [], findings: [], coverage: [], artifacts: [], fixRounds: 0, incomplete: false } as never);
    const dir = harness.store.runDir(project.id, runId);
    mkdirSync(dir, { recursive: true });
    const lines = [1, 2, 3].map((seq) => JSON.stringify({ seq, event: { runId, type: 'log', message: `step ${seq}`, at: new Date().toISOString() } }));
    writeFileSync(join(dir, EVENTS_FILE), `${lines.join('\n')}\n`);

    const res = await request(harness.server).get(`/api/runs/${runId}/events`).set({ Host: '127.0.0.1', Cookie: cookie }).set('Last-Event-ID', '1');
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toContain('text/event-stream');
    // Only the events after the one the page already had.
    expect(res.text).not.toContain('step 1');
    expect(res.text).toContain('step 2');
    expect(res.text).toContain('step 3');
  });

  it('refuses a stream for a run that does not exist', async () => {
    const { cookie } = await signIn(harness);
    const res = await request(harness.server).get('/api/runs/r_20260917120000_dddddd/events').set({ Host: '127.0.0.1', Cookie: cookie });
    expect(res.status).toBe(404);
  });
});
