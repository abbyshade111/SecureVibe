/**
 * `POST /api/projects/:id/runs` (start a build), `GET /api/runs/:id`, `GET /api/runs/:id/events` (SSE),
 * `POST /api/runs/:id/cancel`.
 */
import { Router } from 'express';
import { StartRunRequestSchema, StartRunResponseSchema } from '@shared/api.js';
import {
  cancelRun,
  EVENTS_FILE,
  formatSseEvent,
  formatSseHeartbeat,
  prepareRun,
  readEventsFile,
  readJob,
  signalWorker,
  spawnBuildWorker,
  SSE_HEARTBEAT_MS,
  startRun,
  writeJob,
} from '../pipeline/index.js';
import { join } from 'node:path';
import { forbidden, notFound, validationError } from '../security/errors.js';
import type { SessionRecord } from '../security/token.js';
import { APPROVAL_REFUSAL_TEXT } from './approvals.js';
import { currentPlan } from './plan.js';
import { UPLOADED_EXCLUDED_CHECKS, UPLOADED_IGNORE, UPLOADED_SKIPPED_STAGES, uploadedManifest } from './uploads.js';
import { isUploadedApp } from '@shared/project.js';
import { createProvider } from '../integration.js';
import { SELF_PROJECT_NAME } from '../verification/index.js';
import { notifyRunFinished } from '../notify.js';
import type { ApiDeps } from './types.js';

export function runsRouter(deps: ApiDeps): Router {
  const router = Router();

  router.post('/projects/:id/runs', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    const body = StartRunRequestSchema.parse(req.body);
    const uploaded = isUploadedApp(project);
    if (uploaded && !project.origin?.upload) throw validationError("Upload your app's code before checking it.");
    if (uploaded && !project.design) throw validationError('Answer the questions about your app before checking it.');
    if (body.mode !== 'verify-only' && !project.design) throw validationError('Finish your design before starting a build.');
    if (project.name === SELF_PROJECT_NAME) throw validationError('SecureVibe checks itself from the command line (npm run self-assess), not from here.');
    // Without AI, a full build writes the starter app from the answers (pages for every record, no AI-written
    // features) — free, and the way to see the whole process before spending anything; a re-check re-runs the checks.
    // An uploaded app is only ever checked: nothing is generated or fixed, and nothing runs its code.
    const mode = uploaded ? 'verify-only' : body.mode;

    const settings = deps.config.settings.get();
    const spendingCapUsd = body.spendingCapUsd ?? project.spendingCapUsd ?? settings.defaultSpendingCapUsd;

    // Writing with AI needs the plan the owner approved for this exact design: it is the agent's to-do list and
    // what the result is checked against. Builds without AI write nothing new, so they need no plan.
    const providerFor = body.withoutAi ? () => createProvider({ forceProvider: 'null' }) : deps.getProvider;
    // "Is AI available at all?" is asked of the step that writes the app.
    const provider = providerFor('generate');
    const plan = mode === 'full' && provider.name !== 'null' ? currentPlan(project) : undefined;
    if (mode === 'full' && provider.name !== 'null' && !plan?.approvedAt) {
      throw validationError('Approve the build plan first: it says which features Claude will write, and the result is checked against it.');
    }

    const session = res.locals['session'] as SessionRecord;
    const approval = deps.approvals.consume(body.approvalCode, project.id, session.id, project.design?.profileHash ?? '');
    if (typeof approval === 'string') {
      deps.logger.warn({ event: 'build.approval_refused', reason: approval, projectId: project.id }, 'build approval refused');
      throw forbidden(APPROVAL_REFUSAL_TEXT[approval]);
    }
    deps.logger.info(
      {
        event: 'build.approved',
        projectId: project.id,
        mode,
        sessionRef: approval.sessionRef,
        designHash: approval.designHash,
        estimateUsdHigh: approval.estimateUsdHigh,
        spendingCapUsd,
      },
      'build approved by the owner',
    );

    // A build rewrites the app folder: a preview of the old version stops first.
    deps.previews.stop(project.id);
    const runOptions = {
      mode,
      approval: { ...approval, spendingCapUsd },
      spendingCapUsd,
      ...(body.fixFindingIds && !uploaded ? { fixFindingIds: body.fixFindingIds } : {}),
      ...(plan?.approvedAt ? { plan } : {}),
    };
    // The run record exists before anything runs, so the page has an id to follow. The work itself happens in a
    // separate worker process (pipeline/job.ts): a restart of SecureVibe no longer ends a build.
    const run = prepareRun(project, runOptions, deps.store);
    writeJob(deps.store, {
      projectId: project.id,
      runId: run.id,
      mode,
      spendingCapUsd,
      approval: { ...approval, spendingCapUsd },
      ...(body.fixFindingIds && !uploaded ? { fixFindingIds: body.fixFindingIds } : {}),
      ...(plan?.approvedAt ? { plan } : {}),
      ...(uploaded ? { uploaded: true } : {}),
      ...(body.withoutAi ? { withoutAi: true } : {}),
      createdAt: new Date().toISOString(),
    });
    try {
      const pid = spawnBuildWorker({ store: deps.store, job: readJob(deps.store, project.id, run.id)! });
      deps.logger.info({ event: 'build.worker_started', projectId: project.id, runId: run.id, pid }, 'build worker started');
    } catch (err) {
      // No worker: run it here instead, as before, rather than leaving a run that never starts.
      deps.logger.warn({ err, projectId: project.id, runId: run.id }, 'could not start a build worker; running the build in this process');
      const started = startRun(
        project,
        {
          ...runOptions,
          existingRun: run,
          ...(uploaded
            ? { skipStages: UPLOADED_SKIPPED_STAGES, manifestOverride: uploadedManifest(), extraIgnore: UPLOADED_IGNORE, excludedChecks: UPLOADED_EXCLUDED_CHECKS }
            : {}),
        },
        { store: deps.store, config: deps.config, knowledge: deps.knowledge, frameworks: deps.frameworks, provider, providerFor, busRegistry: deps.busRegistry },
      );
      started
        .execute()
        .then((finished) => notifyRunFinished(deps.config.settings.get(), project, finished))
        .catch((e: unknown) => deps.logger.error({ err: e, projectId: project.id, runId: run.id }, 'pipeline run failed unexpectedly'));
    }

    res.status(202).json(StartRunResponseSchema.parse({ run }));
  });

  router.get('/runs/:id', (req, res) => {
    const run = deps.store.findRun(req.params['id']!);
    if (!run) throw notFound('That run could not be found.');
    res.json({ run });
  });

  router.post('/runs/:id/cancel', (req, res) => {
    const runId = req.params['id']!;
    let cancelled = cancelRun(runId);
    if (!cancelled) {
      const run = deps.store.findRun(runId);
      if (run && run.status === 'running') cancelled = signalWorker(deps.store, run.projectId, runId);
    }
    if (!cancelled) throw notFound('That run is not currently running.');
    res.status(202).json({ cancelling: true });
  });

  router.get('/runs/:id/events', (req, res) => {
    const runId = req.params['id']!;
    // Only existing runs get an event stream, so arbitrary ids cannot create buses that are never freed.
    if (!deps.busRegistry.has(runId) && !deps.store.findRun(runId)) throw notFound('That run could not be found.');
    res.status(200);
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    const lastEventId = req.header('last-event-id');
    const parsedSince = lastEventId ? Number(lastEventId) : undefined;
    const since = Number.isFinite(parsedSince) ? parsedSince : undefined;
    const heartbeat = setInterval(() => res.write(formatSseHeartbeat()), SSE_HEARTBEAT_MS);

    if (deps.busRegistry.has(runId)) {
      const bus = deps.busRegistry.get(runId);
      for (const buffered of bus.since(since)) res.write(formatSseEvent(buffered));
      const unsubscribe = bus.subscribe((buffered) => res.write(formatSseEvent(buffered)));
      req.on('close', () => {
        clearInterval(heartbeat);
        unsubscribe();
      });
      return;
    }

    // A worker process writes the run's events to a file; stream what is there and keep watching it until the
    // run is over (the file's last event is the "done" one, but the run record is the authority).
    const run = deps.store.findRun(runId)!;
    const eventsFile = join(deps.store.runDir(run.projectId, runId), EVENTS_FILE);
    let last = since ?? 0;
    let closed = false;
    const flush = (): boolean => {
      for (const buffered of readEventsFile(eventsFile, last)) {
        res.write(formatSseEvent(buffered));
        last = buffered.seq;
      }
      const current = deps.store.findRun(runId);
      return current !== undefined && current.status !== 'running';
    };
    const tick = (): void => {
      if (closed) return;
      const over = flush();
      if (over) {
        // One last look in case the final events landed after the record was written, then close the stream.
        setTimeout(() => {
          if (closed) return;
          flush();
          clearInterval(heartbeat);
          res.end();
        }, 750);
        return;
      }
      setTimeout(tick, 500);
    };
    tick();
    req.on('close', () => {
      closed = true;
      clearInterval(heartbeat);
    });
  });

  return router;
}
