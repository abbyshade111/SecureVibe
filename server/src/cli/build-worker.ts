#!/usr/bin/env node
/**
 * The build worker: `tsx src/cli/build-worker.ts <projectId> <runId>`.
 *
 * Started by the API (pipeline/job.ts) as a detached process, it reads the job written for the run, executes the
 * pipeline against the run record the API created, appends every progress event to the run's `events.jsonl`, and
 * exits. SIGTERM (from "Cancel" in the UI, or the owner) aborts the run, which is then recorded as cancelled.
 * Everything else — settings, keys, the audit log — comes from the same workspace and `.env` the server uses.
 */
import { join } from 'node:path';
import { loadConfig } from '../config.js';
import { createProvider, loadFrameworks, loadKnowledge } from '../integration.js';
import { providerFactory } from '../llm/active-provider.js';
import { EVENTS_FILE, readJob } from '../pipeline/job.js';
import { RunBusRegistry, fileSink } from '../pipeline/bus.js';
import { cancelRun, startRun } from '../pipeline/runner.js';
import { UPLOADED_EXCLUDED_CHECKS, UPLOADED_IGNORE, UPLOADED_SKIPPED_STAGES, uploadedManifest } from '../api/uploads.js';
import { ProjectStore } from '../store/index.js';
import { summaryOf } from '../pipeline/persist.js';
import { notifyRunFinished } from '../notify.js';

async function main(): Promise<void> {
  const [, , projectId, runId] = process.argv;
  if (!projectId || !runId) throw new Error('usage: build-worker <projectId> <runId>');

  process.stdout.write(`${new Date().toISOString()} build worker started: pid ${process.pid}, parent ${process.ppid}, run ${runId}\n`);
  const config = loadConfig();
  const store = new ProjectStore(config.paths.home);
  const job = readJob(store, projectId, runId);
  const run = store.readRun(projectId, runId);
  if (!job || !run) throw new Error(`No job or run record for ${projectId}/${runId}.`);
  const project = store.mustGet(projectId);

  const eventsFile = join(store.runDir(projectId, runId), EVENTS_FILE);
  const busRegistry = new RunBusRegistry(() => fileSink(eventsFile));
  const provider = job.withoutAi ? createProvider({ forceProvider: 'null' }) : providerFactory(config)();

  const started = startRun(
    project,
    {
      existingRun: run,
      mode: job.mode,
      spendingCapUsd: job.spendingCapUsd,
      ...(job.approval ? { approval: job.approval } : {}),
      ...(job.fixFindingIds ? { fixFindingIds: job.fixFindingIds } : {}),
      ...(job.plan ? { plan: job.plan } : {}),
      ...(job.uploaded
        ? { skipStages: UPLOADED_SKIPPED_STAGES, manifestOverride: uploadedManifest(), extraIgnore: UPLOADED_IGNORE, excludedChecks: UPLOADED_EXCLUDED_CHECKS }
        : {}),
    },
    { store, config, knowledge: loadKnowledge(), frameworks: loadFrameworks(), provider, busRegistry },
  );

  const stop = (signal: NodeJS.Signals): void => {
    process.stdout.write(`${new Date().toISOString()} received ${signal}: cancelling the build\n`);
    cancelRun(runId);
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));

  const finished = await started.execute();
  process.stdout.write(`${new Date().toISOString()} run ${finished.id} ${finished.status}\n`);
  // The owner is usually elsewhere by now: one system notification says how it ended.
  notifyRunFinished(config.settings.get(), project, finished);
}

main().catch((err) => {
  const message = err instanceof Error ? (err.stack ?? err.message) : String(err);
  process.stderr.write(`${new Date().toISOString()} build worker failed: ${message}\n`);
  // Leave an honest record: the run did not finish, and the app is not "building" any more.
  try {
    const [, , projectId, runId] = process.argv;
    if (projectId && runId) {
      const store = new ProjectStore(loadConfig().paths.home);
      const run = store.readRun(projectId, runId);
      if (run && run.status === 'running') {
        run.status = 'failed';
        run.finishedAt = new Date().toISOString();
        run.incomplete = true;
        run.failure = { message: 'The build stopped unexpectedly. The details are in worker.log in the build folder.', options: ['retry'] };
        store.writeRunSync(run);
        store.recordRunSummary(projectId, summaryOf(run));
        store.update(projectId, (p) => {
          if (p.status === 'building') p.status = 'failed';
        });
      }
    }
  } catch {
    // nothing more can be done from here
  }
  process.exit(1);
});
