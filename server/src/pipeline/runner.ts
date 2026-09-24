/**
 * `runPipeline` (CONTRACTS §9.5): runs the stage list from `STAGE_IDS` in order, persisting the run after every
 * stage, streaming progress on the bus, and applying the pipeline's failure rules:
 *  - `install` failing does not stop the run; `typecheck`/`unit-tests`/`dast` are skipped instead;
 *  - a `generate` refusal stops the run immediately;
 *  - any other stage throwing marks it failed, skips the remaining scan stages, and still runs `compliance` and
 *    `reports` with `incomplete: true` — a run never ends with nothing to show for it;
 *  - `verify-only` mode skips `design-freeze`/`scaffold`/`generate`/`fix` and evaluates an application that
 *    already exists.
 */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { TemplateManifestSchema, type TemplateManifest } from '@shared/knowledge.js';
import { PipelineRunSchema, ProvenanceSchema, type PipelineRun, type Provenance, type RunMode, type StageId, type StageResult } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';
import { effectiveAiSettings, type SecureVibeConfig } from '../config.js';
import { newRunId, type ProjectPaths, type ProjectStore } from '../store/index.js';
import type { Frameworks, Knowledge, LlmProvider } from '../integration.js';
import { RunBusRegistry } from './bus.js';
import { runFixLoop } from './fix-loop.js';
import { appendStageLog, markInterruptedRunsAtStartup, summaryOf } from './persist.js';
import { finishStage, skipStage } from './stage-helpers.js';
import { planCoverage } from './plan-coverage.js';
import { ownerTasks } from './owner-tasks.js';
import {
  loadFrozenDesign,
  runAiReviewStage,
  runComplianceStage,
  runConfigStage,
  runDastStage,
  runDepsStage,
  runDesignFreeze,
  runExternalStage,
  runGenerate,
  runInstall,
  runLintStage,
  runReportsStage,
  runSastStage,
  runScaffold,
  runSecretsStage,
  runTypecheck,
  runUnitTestsStage,
} from './stages/index.js';
import { buildScanContext, type PipelineAccumulator, type PipelineCtx } from './types.js';
import { finalizeFindings } from '../scanners/normalize.js';
import { humanReviewIsCurrent } from './human-review.js';
import { finalizeProvenance } from '../generator/provenance.js';
import type { ProviderFor } from '../llm/active-provider.js';
import { promptLibraryHash } from '../llm/index.js';
import { isOpen } from '@shared/findings.js';
import type { GrantedApproval } from '../api/approvals.js';

export { markInterruptedRunsAtStartup };

export interface RunPipelineOptions {
  mode: RunMode;
  /** CLI runs only: a named approver given on the command line. */
  approvedBy?: string;
  /** Builds started from the web app: the owner's checked approval (see api/approvals.ts). */
  approval?: GrantedApproval & { spendingCapUsd: number };
  spendingCapUsd: number;
  fixFindingIds?: string[];
  /** Overrides the application folder that is verified (CLI `verify`/`self-assess`; default `<project>/app`). */
  appDir?: string;
  /** Self-assessment: SecureVibe has no sign-in form, so `dast` needs a bootstrap built from its own startup token. */
  dastAuth?: import('../integration.js').DastAuthBootstrap;
  /** Self-assessment: extra scanner ignore patterns (workspace/, artifacts/, node_modules/, web/dist/, …). */
  extraIgnore?: string[];
  /** Self-assessment: SecureVibe itself ships no `securevibe.manifest.json` (that file describes generated apps). */
  manifestOverride?: TemplateManifest;
  /** Self-assessment `--ai-review-file`: evidence imported from a review performed outside this run. */
  extraEvidence?: import('@shared/compliance.js').Evidence[];
  /** Self-assessment: how `dast` starts and probes SecureVibe itself. */
  dastExtra?: PipelineCtx['dastExtra'];
  /** A run created earlier (by the API) that this process should execute rather than creating a new one. */
  existingRun?: PipelineRun;
  /** The approved feature plan (full builds with AI): given to the agent and checked against the result. */
  plan?: import('@shared/project.js').BuildPlan;
  /** Check ids (finding rule ids and evidence refs) whose results are dropped (uploaded apps: template-only checks). */
  excludedChecks?: string[];
  /** Steps not to run, with the reason shown in the results (uploaded apps: nothing that runs their code). */
  skipStages?: Partial<Record<StageId, string>>;
  /**
   * The Security page's "run this check again": only these checks run, and the compliance verdict and the reports
   * are left alone, because a report written from a handful of checks would understate everything not run.
   */
  onlyChecks?: StageId[];
  /**
   * Continue a build that stopped part-way (see `resumeDecision`). The code already on disk is kept: the app is
   * not laid out again, and the agent is paid to write only what the earlier run had not finished writing.
   */
  resumeFrom?: PipelineRun;
  /** Requirement ids the AI review leaves out (already verified by automated checks). */
  aiReviewSkip?: Set<string>;
  /** Self-assessment: SecureVibe's own test results, used instead of the generated-app test runner. */
  importedTests?: PipelineCtx['importedTests'];
  /** Self-assessment: reviewed rule-level finding decisions with their justification. */
  ruleDecisions?: import('../scanners/normalize.js').RuleDecision[];
}

export interface RunPipelineDeps {
  store: ProjectStore;
  config: SecureVibeConfig;
  knowledge: Knowledge;
  frameworks: Frameworks;
  provider: LlmProvider;
  /** Optional: a provider per step, so writing, reviewing and the questions can use different AI services. */
  providerFor?: ProviderFor;
  busRegistry: RunBusRegistry;
}

/** Abort controllers for runs currently in flight, keyed by run id, so `POST /api/runs/:id/cancel` can reach them. */
const ACTIVE_ABORTS = new Map<string, AbortController>();

/** True while a run is still executing in this process. */
export function isRunActive(runId: string): boolean {
  return ACTIVE_ABORTS.has(runId);
}

export function cancelRun(runId: string): boolean {
  const controller = ACTIVE_ABORTS.get(runId);
  if (!controller) return false;
  controller.abort();
  return true;
}

function emptyAccumulator(seedEvidence: PipelineAccumulator['evidence'] = []): PipelineAccumulator {
  return { findings: [], evidence: [...seedEvidence], coverage: [], testResults: [], probeResults: [], correlationIds: [], servedModels: [] };
}

/**
 * The provenance an earlier run wrote, so a continued run keeps recording who wrote which file rather than
 * starting a fresh record halfway through an app.
 */
function loadProvenanceFromAppDir(appDir: string): Provenance | undefined {
  const file = join(appDir, 'securevibe.provenance.json');
  if (!existsSync(file)) return undefined;
  try {
    return ProvenanceSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return undefined;
  }
}

function loadManifestFromAppDir(appDir: string): TemplateManifest | undefined {
  const file = join(appDir, 'securevibe.manifest.json');
  if (!existsSync(file)) return undefined;
  try {
    return TemplateManifestSchema.parse(JSON.parse(readFileSync(file, 'utf8')));
  } catch {
    return undefined;
  }
}

const CORE_STAGES: { id: StageId; run: (ctx: PipelineCtx) => Promise<StageResult> }[] = [
  { id: 'install', run: runInstall },
  { id: 'typecheck', run: runTypecheck },
  { id: 'lint', run: runLintStage },
  { id: 'unit-tests', run: runUnitTestsStage },
  { id: 'sast', run: runSastStage },
  { id: 'secrets', run: runSecretsStage },
  { id: 'deps', run: runDepsStage },
  { id: 'config', run: runConfigStage },
  { id: 'dast', run: runDastStage },
  { id: 'external', run: runExternalStage },
  { id: 'ai-review', run: runAiReviewStage },
];

/**
 * What a continued build may skip.
 *
 * A build that stopped leaves its work on disk: the app folder as the scaffold laid it out, plus whatever the agent
 * had written. Two things are worth not paying for again. Laying out the app is deterministic, so it is never
 * repeated; writing the app costs real money, so it is repeated only when the earlier run had not finished it.
 *
 * Everything after that is always re-run. Checks are cheap, they are what the report rests on, and a check carried
 * over from an earlier run would be a claim about code that has since changed.
 */
export function resumeDecision(previous: PipelineRun): { skipScaffold: true; skipGenerate: boolean; note: string } {
  const generate = previous.stages.find((s) => s.id === 'generate');
  const wroteEverything = generate?.status === 'passed' || generate?.status === 'skipped';
  return {
    skipScaffold: true,
    skipGenerate: wroteEverything,
    note: wroteEverything
      ? 'Continued from the earlier build, which had nothing left to write: nothing was written again, and every check was run afresh.'
      : 'Continued from the earlier build, which stopped while writing your app: the parts it had already written were kept, and the rest was written from there.',
  };
}

export interface StartedRun {
  run: PipelineRun;
  /** Runs the pipeline to completion in the background. Call once; the run's progress is visible over SSE. */
  execute(): Promise<PipelineRun>;
}

/**
 * Creates and persists the run record synchronously (so the caller has a run id to respond with immediately),
 * then hands back a thunk that does the actual work. Splitting these two halves means the API route never has
 * to guess or poll for the run id `runPipeline` would otherwise generate internally.
 */
export function startRun(project: Project, opts: RunPipelineOptions, deps: RunPipelineDeps): StartedRun {
  const runId = opts.existingRun?.id ?? newRunId();
  const paths: ProjectPaths = deps.store.paths(project.id);
  const appDir = opts.appDir ?? paths.appDir;
  const abort = new AbortController();
  ACTIVE_ABORTS.set(runId, abort);

  const startedAt = new Date().toISOString();
  const approvedBy = opts.approval?.approvedBy ?? opts.approvedBy;
  const approvedAt = opts.approval?.approvedAt ?? startedAt;
  // A run the API already created (for a worker to execute) keeps its record; otherwise a new one is written.
  const run: PipelineRun = opts.existingRun ?? PipelineRunSchema.parse({
    id: runId,
    projectId: project.id,
    mode: opts.mode,
    startedAt,
    status: 'running',
    stages: [],
    spendingCapUsd: opts.spendingCapUsd,
    ...(approvedBy ? { approvedBy, approvedAt } : {}),
    ...(opts.approval
      ? {
          approval: {
            sessionRef: opts.approval.sessionRef,
            designHash: opts.approval.designHash,
            estimateUsdHigh: opts.approval.estimateUsdHigh,
            estimateShownAt: opts.approval.estimateShownAt,
            spendingCapUsd: opts.approval.spendingCapUsd,
          },
        }
      : {}),
  });
  deps.store.writeRunSync(run);
  // The app list shows what is happening now; the run's own status is what the pipeline writes below.
  deps.store.update(project.id, (p) => {
    p.status = 'building';
  });

  const bus = deps.busRegistry.get(runId);
  const settings = effectiveAiSettings(deps.config.settings.get());

  const ctx: PipelineCtx = {
    store: deps.store,
    config: deps.config,
    settings,
    project,
    run,
    paths,
    appDir,
    knowledge: deps.knowledge,
    frameworks: deps.frameworks,
    provider: deps.provider,
    providerFor: (purpose) => deps.providerFor?.(purpose) ?? deps.provider,
    bus,
    abort,
    acc: emptyAccumulator(opts.extraEvidence),
    fixFindingIds: opts.fixFindingIds ?? [],
    spendingCapUsd: opts.spendingCapUsd,
    ...(approvedBy ? { approvedBy } : {}),
    ...(opts.dastAuth ? { dastAuth: opts.dastAuth } : {}),
    ...(opts.extraIgnore ? { extraIgnore: opts.extraIgnore } : {}),
    ...(opts.ruleDecisions ? { ruleDecisions: opts.ruleDecisions } : {}),
    ...(opts.excludedChecks ? { excludedChecks: new Set(opts.excludedChecks) } : {}),
    ...(opts.plan ? { plan: opts.plan } : {}),
    ...(opts.importedTests ? { importedTests: opts.importedTests } : {}),
    ...(opts.dastExtra ? { dastExtra: opts.dastExtra } : {}),
    ...(opts.aiReviewSkip ? { aiReviewSkip: opts.aiReviewSkip } : {}),
    ...(opts.manifestOverride ? { manifest: opts.manifestOverride } : {}),
    log: (stage, message) => {
      bus.log(message, stage);
      // Also kept in the stage's log file, so warnings and security notes survive the live view.
      try {
        appendStageLog(deps.store, project.id, runId, stage, message);
      } catch {
        // a log write must never break the build
      }
    },
  };

  const persist = async (): Promise<void> => {
    await deps.store.writeRun(run);
  };
  const push = async (result: StageResult): Promise<void> => {
    run.stages.push(result);
    await persist();
  };

  const execute = async (): Promise<PipelineRun> => {
    try {
    const resume = opts.resumeFrom ? resumeDecision(opts.resumeFrom) : undefined;
    if (resume) {
      run.resumedFrom = opts.resumeFrom!.id;
      run.resumedNote = resume.note;
    }
    // Before anything may write: a continued run skips scaffold, and scaffold is what normally puts the app's
    // manifest and provenance on the context. Loading them after the generate branch — which is where this used
    // to happen — meant a resumed build reached generate with no manifest and refused with "the application was
    // not ready to be written yet". So a build interrupted while writing, which is the case resume exists for,
    // could never be continued: an owner whose AI credit ran out mid-build was stuck for good. A fresh build
    // overwrites both from scaffold a moment later, so this costs nothing there.
    if (!ctx.manifest) ctx.manifest = loadManifestFromAppDir(appDir);
    if (!ctx.provenance) ctx.provenance = loadProvenanceFromAppDir(appDir);

    if (opts.mode === 'verify-only') {
      if (project.design) ctx.design = project.design;
      await push(loadFrozenDesign(ctx));
      // Say so, rather than leaving them pending for ever. A check-only run never lays the app out again and
      // never writes code, and a step with no status reads as one that is still to come: the list showed two
      // steps waiting that were never going to happen, and the progress bar counted them as work outstanding.
      await push(skipStage(ctx, 'scaffold', 'Your app was not laid out again: this run only checks the code that is already there.'));
      await push(skipStage(ctx, 'generate', 'Nothing was written and nothing was spent: this run only checks the code that is already there.'));
    } else if (resume) {
      // The design was frozen by the run being continued; freezing it again would only rewrite the same documents.
      if (project.design) ctx.design = project.design;
      await push(loadFrozenDesign(ctx));
      await push(skipStage(ctx, 'scaffold', 'Your app was already laid out by the build this one continues, so it was kept as it was.'));
      if (resume.skipGenerate) {
        await push(skipStage(ctx, 'generate', 'The build this one continues had finished writing your app, so nothing was written again (and nothing was spent on it).'));
      } else {
        const generated = await runGenerate(ctx);
        await push(generated.result);
        if (generated.hardStop) {
          run.failure = generated.hardStop;
          return finish(ctx, run, deps, 'failed');
        }
      }
    } else {
      const freeze = await runDesignFreeze(ctx);
      await push(freeze);
      if (freeze.status !== 'passed') return finish(ctx, run, deps, 'failed');

      const scaffold = await runScaffold(ctx);
      await push(scaffold);
      if (scaffold.status !== 'passed') return finish(ctx, run, deps, 'failed');

      const generated = await runGenerate(ctx);
      await push(generated.result);
      if (generated.hardStop) {
        run.failure = generated.hardStop;
        return finish(ctx, run, deps, 'failed');
      }
    }

    if (!ctx.manifest) ctx.manifest = loadManifestFromAppDir(appDir);

    let crashedAt: StageId | undefined;
    // A partial run still installs packages: the checks that follow cannot run without them.
    const onlyChecks = opts.onlyChecks?.length ? new Set<StageId>([...opts.onlyChecks, 'install']) : undefined;
    for (const stage of CORE_STAGES) {
      if (abort.signal.aborted) break;
      const notAskedFor = onlyChecks && !onlyChecks.has(stage.id) ? 'You asked for some of the checks only, so this one was not run this time. What it says is the result of the last run that did include it.' : undefined;
      const skipReason = opts.skipStages?.[stage.id] ?? notAskedFor;
      if (skipReason) {
        await push(skipStage(ctx, stage.id, skipReason));
        continue;
      }
      try {
        await push(await stage.run(ctx));
      } catch (err) {
        crashedAt = stage.id;
        run.incomplete = true;
        await push(
          finishStage(ctx, stage.id, 'failed', `This step stopped unexpectedly: ${err instanceof Error ? err.message : String(err)}. The rest of the checks were skipped, but the build is still evaluated with what was found.`, new Date()),
        );
        break;
      }
    }
    if (crashedAt) {
      const skipFrom = CORE_STAGES.findIndex((s) => s.id === crashedAt) + 1;
      for (const stage of CORE_STAGES.slice(skipFrom)) {
        await push(finishStage(ctx, stage.id, 'skipped', 'Skipped because an earlier step stopped unexpectedly.', new Date(), { skippedReason: 'earlier stage crashed' }));
      }
    }

    finalizeRunFindings(ctx, deps);
    // Was each planned feature actually built? Measured against the route list, the record types and the tests.
    if (ctx.plan && opts.mode !== 'verify-only') run.planCoverage = planCoverage(ctx.plan, appDir, ctx.acc.testResults);
    // What only the owner can do: empty settings, services without an address or key, features not built.
    if (ctx.profile) run.ownerTasks = ownerTasks({ profile: ctx.profile, appDir, planCoverage: run.planCoverage });

    if (opts.mode === 'verify-only') {
      await push(skipStage(ctx, 'fix', 'Nothing was fixed: this run only reports what it found, and fixing is part of a build.'));
    } else if (!crashedAt && !abort.signal.aborted) {
      await push(await runFixLoop(ctx));
    } else {
      await push(finishStage(ctx, 'fix', 'skipped', abort.signal.aborted ? 'The build was cancelled.' : 'Skipped because an earlier step stopped unexpectedly.', new Date()));
    }

    finalizeRunProvenance(ctx);
    if (onlyChecks) {
      // Only some checks ran, so there is nothing honest to say about compliance as a whole: the verdict and the
      // reports on file stay as the last full check left them.
      run.partial = true;
      run.partialChecks = opts.onlyChecks!;
      const reason = 'Only some checks were run, so the compliance report was left as your last full check made it.';
      await push(skipStage(ctx, 'compliance', reason));
      await push(skipStage(ctx, 'reports', reason));
    } else {
      await push(await runComplianceStage(ctx));
      await push(await runReportsStage(ctx));
    }

      const finalStatus = abort.signal.aborted ? 'cancelled' : run.failure || crashedAt ? 'failed' : 'succeeded';
      return finish(ctx, run, deps, finalStatus);
    } finally {
      ACTIVE_ABORTS.delete(runId);
    }
  };

  return { run, execute };
}

/**
 * Normalizes the findings once every scanner has run (CONTRACTS §9.2): de-duplication, deployment-aware severity,
 * priority, the person's saved accept/false-positive decisions, continuity with the previous run and stable ids.
 */
function finalizeRunFindings(ctx: PipelineCtx, deps: RunPipelineDeps): void {
  if (!ctx.buildSpec || !ctx.manifest) return; // nothing was scanned (the build stopped before scaffolding)
  const previousId = deps.store.listRunIds(ctx.project.id).filter((id) => id < ctx.run.id).at(-1);
  const previousFindings = previousId ? deps.store.readRun(ctx.project.id, previousId)?.findings : undefined;
  // "Fix these" ids were chosen on the previous run's results; ids are reassigned every run, fingerprints are stable.
  if (previousFindings && ctx.fixFindingIds.length > 0) {
    ctx.fixFindingIds = ctx.fixFindingIds.map((id) => previousFindings.find((f) => f.id === id)?.fingerprint ?? id);
  }
  ctx.acc.findings = finalizeFindings(ctx.acc.findings, buildScanContext(ctx, 'compliance'), {
    deploymentTarget: ctx.profile?.deployment.target ?? ctx.project.profile?.deployment?.target ?? 'local-only',
    decisions: ctx.project.findingDecisions,
    ...(ctx.ruleDecisions ? { ruleDecisions: ctx.ruleDecisions } : {}),
    ...(previousFindings ? { previousFindings } : {}),
    runId: ctx.run.id,
  });
  noteReviewedFindings(ctx);
}

/**
 * Completes the provenance record once the code can no longer change (after the fix loop): the hash of the exact
 * tree that is assessed, framework and tool versions, the AI calls made, and what people did.
 */
function finalizeRunProvenance(ctx: PipelineCtx): void {
  if (!ctx.provenance || !existsSync(ctx.appDir)) return;
  const toolVersions: Record<string, string> = {};
  for (const c of ctx.acc.coverage) if (c.ran && c.version) toolVersions[c.tool] = c.version;
  const suggestions = ctx.design?.peerReview?.suggestions ?? [];
  const peerReviewDecisions = suggestions.filter((sug) => sug.accepted !== null).map((sug) => ({ suggestionId: sug.id, accepted: sug.accepted === true }));
  const approval = ctx.run.approvedBy
    ? `Build approved by ${ctx.run.approvedBy}${ctx.run.approvedAt ? ` on ${ctx.run.approvedAt.slice(0, 10)}` : ''} before any code was generated${
        ctx.run.approval
          ? `, after seeing an AI cost estimate of up to $${ctx.run.approval.estimateUsdHigh.toFixed(2)} and setting a $${ctx.run.approval.spendingCapUsd.toFixed(2)} spending limit`
          : ''
      }.`
    : 'No build approval is recorded for this run.';
  const attestations = ctx.project.attestations.length;
  const finalized = finalizeProvenance(ctx.provenance, {
    frameworkVersions: { asvs: ctx.frameworks.asvs.version, aisvs: ctx.frameworks.aisvs.version, sbd: ctx.frameworks.sbd.version },
    toolVersions,
    ...(ctx.acc.correlationIds.length > 0
      ? {
          llm: {
            // Steps may run on different services; the record names each one that could have been used.
            provider: [...new Set([ctx.providerFor('generate').name, ctx.providerFor('fix').name, ctx.providerFor('ai-review').name])].filter((n) => n !== 'null').join(', ') || ctx.provider.name,
            requestedModel: ctx.providerFor('generate').model,
            servedModels: [...new Set(ctx.acc.servedModels)],
            promptHashes: [],
            correlationIds: ctx.acc.correlationIds,
            promptLibraryHash: promptLibraryHash(),
          },
        }
      : {}),
    humanInvolvement: {
      summary: `${approval} ${peerReviewDecisions.length} design suggestion(s) decided by the owner; ${attestations} answer(s) recorded for checks only a person can confirm.`,
      peerReviewDecisions,
      attestations,
      humanCodeReview: false,
    },
    appDir: ctx.appDir,
    protectedFileHashes: ctx.provenance.protectedFileHashes,
  });
  // A recorded human review counts only for the exact code tree that was reviewed.
  finalized.humanInvolvement.humanCodeReview = humanReviewIsCurrent(ctx);
  ctx.provenance = finalized;
}

const SCAN_STAGES: StageId[] = ['lint', 'sast', 'secrets', 'deps', 'config', 'dast'];

/**
 * Scanner stages summarise their raw findings. When saved decisions marked some of them accepted or false
 * positive, say so in the stage line and base the stage status on what is still open.
 */
function noteReviewedFindings(ctx: PipelineCtx): void {
  for (const stage of ctx.run.stages) {
    if (!SCAN_STAGES.includes(stage.id) || stage.status === 'skipped') continue;
    const mine = ctx.acc.findings.filter((f) => f.source === stage.id);
    const reviewed = mine.filter((f) => f.status === 'accepted' || f.status === 'false-positive').length;
    if (reviewed === 0) continue;
    const open = mine.filter((f) => isOpen(f));
    stage.summary = `${stage.summary} After merging duplicates and review: ${mine.length} distinct, ${reviewed} accepted or false positive (reasons in the security report), ${open.length} open.`;
    stage.status = open.some((f) => f.severity === 'critical' || f.severity === 'high') ? 'failed' : open.length > 0 ? 'warning' : 'passed';
  }
}

/**
 * Creates and persists the run record only (status "running", app marked "building"), for a separate worker
 * process to execute with `startRun(..., { existingRun })`. Mirrors the top of `startRun` exactly.
 */
export function prepareRun(project: Project, opts: Omit<RunPipelineOptions, 'existingRun'>, store: ProjectStore): PipelineRun {
  const startedAt = new Date().toISOString();
  const approvedBy = opts.approval?.approvedBy ?? opts.approvedBy;
  const approvedAt = opts.approval?.approvedAt ?? startedAt;
  const run: PipelineRun = PipelineRunSchema.parse({
    id: newRunId(),
    projectId: project.id,
    mode: opts.mode,
    startedAt,
    status: 'running',
    stages: [],
    spendingCapUsd: opts.spendingCapUsd,
    ...(approvedBy ? { approvedBy, approvedAt } : {}),
    ...(opts.approval
      ? {
          approval: {
            sessionRef: opts.approval.sessionRef,
            designHash: opts.approval.designHash,
            estimateUsdHigh: opts.approval.estimateUsdHigh,
            estimateShownAt: opts.approval.estimateShownAt,
            spendingCapUsd: opts.approval.spendingCapUsd,
          },
        }
      : {}),
  });
  store.writeRunSync(run);
  // The project points at this run from the moment it exists, not from the moment it finishes. Until 24 September
  // 2026 lastRunId was set only by finish(), so for the whole of a build the record named the previous run: the
  // Results page showed old results, "Continue" opened an old build, and nothing anywhere could find the live one.
  store.recordRunSummary(project.id, summaryOf(run));
  store.update(project.id, (p) => {
    p.status = 'building';
  });
  return run;
}

/** Creates the run and immediately runs it to completion — used by the CLI, where nothing needs the run id early. */
export async function runPipeline(project: Project, opts: RunPipelineOptions, deps: RunPipelineDeps): Promise<PipelineRun> {
  return startRun(project, opts, deps).execute();
}

async function finish(ctx: PipelineCtx, run: PipelineRun, deps: RunPipelineDeps, status: PipelineRun['status']): Promise<PipelineRun> {
  run.findings = ctx.acc.findings;
  run.coverage = ctx.acc.coverage;
  if (ctx.provenance) run.provenance = ctx.provenance;
  run.status = status;
  run.finishedAt = new Date().toISOString();
  await deps.store.writeRun(run);
  deps.store.recordRunSummary(run.projectId, summaryOf(run));
  // What the owner sees in "My apps": a finished run means the code on disk matches the answers it was built from.
  deps.store.update(run.projectId, (p) => {
    if (status === 'succeeded') {
      p.status = 'built';
      p.buildStale = false;
      p.designStale = false;
    } else if (status === 'failed') {
      p.status = 'failed';
    } else if (p.status === 'building') {
      // Cancelled or interrupted: back to where it was, so the buttons make sense again.
      p.status = p.runs.some((r) => r.status === 'succeeded') ? 'built' : 'designed';
    }
  });
  ctx.bus.done(
    status === 'succeeded' ? 'The build finished.' : status === 'cancelled' ? 'The build was cancelled.' : (run.failure?.message ?? 'The build did not finish.'),
  );
  return run;
}
