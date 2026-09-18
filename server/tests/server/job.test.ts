/** Durable builds: the job file, the worker record, liveness, and the events file the server tails. */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { loadConfig } from '../../src/config.js';
import { RunBus, RunBusRegistry, fileSink, readEventsFile } from '../../src/pipeline/bus.js';
import { readJob, readWorker, runIsLive, workerIsAlive, writeJob, WORKER_FILE } from '../../src/pipeline/job.js';
import { markInterruptedRunsAtStartup } from '../../src/pipeline/persist.js';
import { ProjectStore } from '../../src/store/index.js';
import { habitTracker } from '../fixtures/design/profiles.js';

describe('durable builds', () => {
  let home: string;
  let store: ProjectStore;

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'securevibe-job-'));
    store = new ProjectStore(loadConfig({ ...process.env, SECUREVIBE_HOME: home }).paths.home);
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function runningRun(projectId: string, runId: string) {
    store.writeRunSync({ id: runId, projectId, mode: 'full', startedAt: new Date().toISOString(), status: 'running', stages: [], findings: [], coverage: [], artifacts: [], fixRounds: 0, incomplete: false } as never);
    store.update(projectId, (p) => {
      p.lastRunId = runId;
    });
  }

  it('writes and reads the job a worker needs', () => {
    const project = store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const runId = 'r_20260917120000_aaaaaa';
    writeJob(store, { projectId: project.id, runId, mode: 'full', spendingCapUsd: 5, withoutAi: true, createdAt: 'now' });
    expect(readJob(store, project.id, runId)).toMatchObject({ mode: 'full', spendingCapUsd: 5, withoutAi: true });
    expect(readJob(store, project.id, 'r_20260917120000_zzzzzz')).toBeUndefined();
  });

  it('knows whether a worker is alive, and treats a live worker as a running build', () => {
    const project = store.create({ name: 'Habits', mode: 'guided', profile: habitTracker });
    const runId = 'r_20260917120000_bbbbbb';
    runningRun(project.id, runId);
    expect(runIsLive(store, runId)).toBe(false);

    // This test process stands in for a live worker; a pid that cannot exist stands in for a dead one.
    writeFileSync(join(store.runDir(project.id, runId), WORKER_FILE), JSON.stringify({ pid: process.pid, startedAt: 'now' }));
    expect(readWorker(store, project.id, runId)?.pid).toBe(process.pid);
    expect(workerIsAlive(store, project.id, runId)).toBe(true);
    expect(runIsLive(store, runId)).toBe(true);
    // A restart of SecureVibe leaves a run with a live worker alone…
    expect(markInterruptedRunsAtStartup(store)).toEqual([]);
    expect(store.readRun(project.id, runId)?.status).toBe('running');

    writeFileSync(join(store.runDir(project.id, runId), WORKER_FILE), JSON.stringify({ pid: 2147483000, startedAt: 'now' }));
    expect(workerIsAlive(store, project.id, runId)).toBe(false);
    expect(runIsLive(store, runId)).toBe(false);
    // …and marks one whose worker is gone as interrupted.
    expect(markInterruptedRunsAtStartup(store)).toEqual([runId]);
    expect(store.readRun(project.id, runId)?.status).toBe('interrupted');
  });

  it('streams every event through the events file, in order, and only what is new', () => {
    const file = join(home, 'events.jsonl');
    const registry = new RunBusRegistry(() => fileSink(file));
    const bus = registry.get('r_1');
    bus.log('one');
    bus.stage('scaffold', 'passed', 'two');
    bus.done('three');
    const all = readEventsFile(file);
    expect(all.map((b) => b.seq)).toEqual([1, 2, 3]);
    expect(all.map((b) => b.event.message)).toEqual(['one', 'two', 'three']);
    expect(readEventsFile(file, 2).map((b) => b.event.type)).toEqual(['done']);
    // A bus without a sink still works as before.
    const plain = new RunBus('r_2');
    plain.log('x');
    expect(plain.since().length).toBe(1);
  });
});
