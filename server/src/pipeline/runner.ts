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
import { PipelineRunSchema, type PipelineRun, type RunMode, type StageId, type StageResult } from '@shared/pipeline.js';
import type { Project } from '@shared/project.js';
import { effectiveAiSettings, type SecureVibeConfig } from '../config.js';
import { newRunId, type ProjectPaths, type ProjectStore } from '../store/index.js';
import type { Frameworks, Knowledge, LlmProvider } from '../integration.js';
import { RunBusRegistry } from './bus.js';
import { runFixLoop } from './fix-loop.js';
import { appendStageLog, markInterruptedRunsAtStartup, summaryOf } from './persist.js';
import { finishStage, skipStage } from './stage-helpers.js';
import { planCoverage } from './plan-coverage.js';
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
    if (opts.mode === 'verify-only') {
      if (project.design) ctx.design = project.design;
      await push(loadFrozenDesign(ctx));
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
    for (const stage of CORE_STAGES) {
      if (abort.signal.aborted) break;
      const skipReason = opts.skipStages?.[stage.id];
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

    if (opts.mode !== 'verify-only' && !crashedAt && !abort.signal.aborted) {
      await push(await runFixLoop(ctx));
    } else if (opts.mode !== 'verify-only') {
      await push(finishStage(ctx, 'fix', 'skipped', abort.signal.aborted ? 'The build was cancelled.' : 'Skipped because an earlier step stopped unexpectedly.', new Date()));
    }

    finalizeRunProvenance(ctx);
    await push(await runComplianceStage(ctx));
    await push(await runReportsStage(ctx));

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
