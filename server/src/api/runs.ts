/**
 * `POST /api/projects/:id/runs` (start a build), `GET /api/runs/:id`, `GET /api/runs/:id/events` (SSE),
 * `POST /api/runs/:id/cancel`.
 */
import { Router } from 'express';
import { ChecksResponseSchema, StartRunRequestSchema, StartRunResponseSchema, type CheckStatus, type ChecksResponse } from '@shared/api.js';
import {
  cancelRun,
  EVENTS_FILE,
  formatSseEvent,
  formatSseHeartbeat,
  prepareRun,
  readEventsFile,
  readJob,
  runIsLive,
  signalWorker,
  spawnBuildWorker,
  SSE_HEARTBEAT_MS,
  startRun,
  writeJob,
} from '../pipeline/index.js';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { RERUNNABLE_CHECKS, STAGE_DESCRIPTIONS, type PipelineRun, type StageId } from '@shared/pipeline.js';
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

    // "Run this check again" from the Security page: only these checks, and only ones that cost nothing.
    const checks = body.checks?.length ? body.checks.filter((c) => (RERUNNABLE_CHECKS as readonly string[]).includes(c)) : undefined;
    if (body.checks?.length && !checks?.length) throw validationError('Those are not checks that can be run on their own.');

    /**
     * Continuing a build that stopped. Only honest when the code on disk is the code that run wrote for this design:
     * a different design, or a missing app folder, means there is nothing to continue and the build starts over.
     */
    let resumeFrom: PipelineRun | undefined;
    if (body.resumeFromRunId) {
      const previous = deps.store.readRun(project.id, body.resumeFromRunId);
      if (!previous) throw validationError('That build could not be found, so there is nothing to continue.');
      if (previous.status === 'running') throw validationError('That build is still going. Watch it, or stop it first.');
      if (previous.status === 'succeeded') throw validationError('That build finished, so there is nothing to continue. Build again instead.');
      if (!existsSync(join(deps.store.paths(project.id).appDir, 'package.json'))) {
        throw validationError('The app folder from that build is not there any more, so it has to be built from the start.');
      }
      const designHash = project.design?.profileHash;
      // No provenance means the earlier run died before it recorded which answers it was building from, so a
      // change of answers cannot be detected and continuing could lay new code onto a folder built from the old
      // ones — exactly what the refusal below promises cannot happen. A run that early has nothing worth keeping.
      if (!previous.provenance?.designProfileHash) {
        throw validationError('That build stopped too early to be continued safely: it never recorded which answers it was building from. Start a fresh build instead.');
      }
      if (designHash && previous.provenance?.designProfileHash && previous.provenance.designProfileHash !== designHash) {
        throw validationError('Your answers have changed since that build, so continuing it would build the wrong app. Start a fresh build instead.');
      }
      resumeFrom = previous;
    }

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
      ...(checks ? { onlyChecks: checks } : {}),
      ...(resumeFrom ? { resumeFrom } : {}),
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
      ...(checks ? { checks } : {}),
      ...(resumeFrom ? { resumeFromRunId: resumeFrom.id } : {}),
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

  /**
   * The Security page: what each check said, and when. A check that was not part of the last run keeps the result
   * of the last run that did include it, so re-running one check never makes the others look like they vanished.
   */
  router.get('/projects/:id/checks', (req, res) => {
    const project = deps.store.mustGet(req.params['id']!);
    // Every run, newest first, and stop as soon as there is nothing left to learn.
    //
    // This used to read only the last ten runs, which broke by being used exactly as intended: each "Run this
    // one" makes a run of its own, and a single-check run marks the other eight stages skipped, which says
    // nothing about them. After ten of those the whole window held nothing but partial runs, so every check the
    // owner had not personally re-run read "This check has not run for your app yet" and the page announced that
    // the app had never had a full check. Both false, with the real answers sitting in older run records on disk.
    // A ceiling on how far back to look is a ceiling on the truth. The reads are small JSON files and the loop
    // ends the moment every check is answered and a full check is found, so in the ordinary case it stops after
    // one or two.
    const runIds = deps.store.listRunIds(project.id).reverse();
    const found = new Map<StageId, CheckStatus>();
    let lastFullCheck: ChecksResponse['lastFullCheck'];
    let running = false;

    for (const runId of runIds) {
      if (found.size === RERUNNABLE_CHECKS.length && lastFullCheck) break;
      const run = deps.store.readRun(project.id, runId);
      if (!run) continue;
      // "running" has to mean a run that is really executing, not one whose status was never written again.
      // A worker that is killed — the machine sleeps, SecureVibe is stopped mid-check, the process dies — leaves
      // its run saying "running" for ever, and this page then disables every button on it permanently, with no way
      // back. runIsLive asks whether the process is actually there, which is what the rest of the API already does.
      if (run.status === 'running' && runIsLive(deps.store, run.id)) running = true;
      for (const check of RERUNNABLE_CHECKS) {
        if (found.has(check)) continue;
        const stage = run.stages.find((s) => s.id === check);
        // A stage that was skipped says nothing about the app, so an older run that really ran it is the truth.
        if (!stage || stage.status === 'skipped' || stage.status === 'running') continue;
        found.set(check, {
          id: check,
          title: STAGE_DESCRIPTIONS[check].title,
          covers: STAGE_DESCRIPTIONS[check].why,
          status: stage.status === 'passed' || stage.status === 'failed' || stage.status === 'warning' ? stage.status : 'skipped',
          summary: stage.summary,
          ...(stage.finishedAt ? { ranAt: stage.finishedAt } : {}),
          runId: run.id,
          findingCounts: countsFor(run, check),
        });
      }
      if (!lastFullCheck && !run.partial && run.status !== 'running') {
        lastFullCheck = { runId: run.id, ...(run.finishedAt ? { finishedAt: run.finishedAt } : {}), status: run.status };
      }
    }

    const body: ChecksResponse = {
      checks: RERUNNABLE_CHECKS.map(
        (check) =>
          found.get(check) ?? {
            id: check,
            title: STAGE_DESCRIPTIONS[check].title,
            covers: STAGE_DESCRIPTIONS[check].why,
            status: 'never-run' as const,
            summary: 'This check has not run for your app yet.',
          },
      ),
      ...(lastFullCheck ? { lastFullCheck } : {}),
      running,
    };
    res.json(ChecksResponseSchema.parse(body));
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

/** How many open problems one check found in a run, by severity (the Security page shows them next to the check). */
function countsFor(run: PipelineRun, check: StageId): Record<string, number> | undefined {
  // The app's own test suite is the `unit-tests` step; its findings are recorded as `tests`.
  const sources: string[] = check === 'unit-tests' ? ['tests'] : [check];
  const counts: Record<string, number> = {};
  for (const finding of run.findings) {
    if (!sources.includes(finding.source)) continue;
    if (finding.status !== 'open' && finding.status !== 'fix-attempted') continue;
    counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  }
  return Object.keys(counts).length ? counts : undefined;
}
