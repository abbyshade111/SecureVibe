/**
 * `fix`: Claude repairs the findings that matter (CONTRACTS §9.5). Only findings the tool itself is confident
 * about are offered — P1/P2 priority, and never an AI-review finding with less than high confidence, since that
 * evidence is already the weakest kind SecureVibe collects.
 *
 * A finding only counts as `fixed` when, after a fresh re-run of every deterministic check, its own detector no
 * longer reports it, no new P1/P2 finding appeared, the passing-test count did not drop, and every protected file
 * still has its scaffold-time hash. Anything short of that is `fix-attempted`, not `fixed` — the fix loop never
 * takes Claude's word for its own success.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { isOpen, sortFindings, type Finding } from '@shared/findings.js';
import type { StageResult } from '@shared/pipeline.js';
import {
  DEFAULT_BUDGETS,
  attributeAttempts,
  finalizeFindings,
  fixFindings,
  mergeUsage,
  runConfig,
  runDast,
  runDeps,
  runLint,
  runSast,
  runSecrets,
  runTests,
} from '../integration.js';
import { computeProtectedFileHashes, listFiles, refreshDerivedFiles } from '../generator/index.js';
import { buildFixBrief } from '../generator/brief.js';
import { markGeneratedFiles } from '../generator/provenance.js';
import { makeRunCheck } from './checks.js';
import { unifiedDiff } from './diff.js';
import { MIN_STAGE_BUDGET_USD, budgetExhaustedText, finishStage, securityEventLine, remainingBudgetUsd, stageBudgetUsd, startStage } from './stage-helpers.js';
import { buildScanContext, type PipelineCtx } from './types.js';

const MAX_CANDIDATES_PER_ROUND = 15;

/** `extraIds` holds finding ids or fingerprints (the runner translates ids chosen on a previous run's results). */
function selectCandidates(findings: Finding[], extraIds: string[]): Finding[] {
  const wanted = new Set(extraIds);
  const extra = findings.filter((f) => wanted.has(f.fingerprint) || wanted.has(f.id));
  const priorityCandidates = findings.filter(
    (f) => isOpen(f) && (f.priority === 'P1' || f.priority === 'P2') && !(f.source === 'ai-review' && f.confidence !== 'high'),
  );
  const merged = new Map<string, Finding>();
  for (const f of [...priorityCandidates, ...extra]) merged.set(f.id, f);
  return [...merged.values()].slice(0, MAX_CANDIDATES_PER_ROUND);
}

function snapshotFiles(appDir: string): Map<string, string> {
  const snap = new Map<string, string>();
  for (const f of listFiles(appDir)) {
    try {
      snap.set(f.relPath, readFileSync(f.absPath, 'utf8'));
    } catch {
      // binary or unreadable; diffs for it are skipped
    }
  }
  return snap;
}

interface RescanSnapshot {
  findings: Finding[];
  evidence: PipelineCtx['acc']['evidence'];
  coverage: PipelineCtx['acc']['coverage'];
  testResults: PipelineCtx['acc']['testResults'];
  probeResults: PipelineCtx['acc']['probeResults'];
}

/** Re-runs every deterministic check (typecheck through dast). Returns a fresh, self-contained snapshot — it
 * does not touch `ctx.acc` itself, so "before" and "after" can be compared without one overwriting the other. */
async function rescan(ctx: PipelineCtx, round: number, previousFindings: Finding[]): Promise<RescanSnapshot> {
  const raw: Finding[] = [];
  const evidence: RescanSnapshot['evidence'] = [];
  const coverage: RescanSnapshot['coverage'] = [];
  const testResults: RescanSnapshot['testResults'] = [];
  const probeResults: RescanSnapshot['probeResults'] = [];

  const started0 = new Date();
  const typecheckOutcome = await makeRunCheck(ctx)('typecheck');
  ctx.run.stages.push(
    finishStage(ctx, 'typecheck', typecheckOutcome.ok ? 'passed' : 'failed', typecheckOutcome.ok ? 'Type check passed.' : 'Type check still fails.', started0, { round }),
  );

  const run = async (stage: 'lint' | 'sast' | 'secrets' | 'deps' | 'config' | 'unit-tests' | 'dast', scanFn: () => ReturnType<typeof runLint>) => {
    const started = new Date();
    const result = await scanFn();
    raw.push(...result.findings);
    evidence.push(...result.evidence);
    coverage.push(result.coverage);
    ctx.run.stages.push(finishStage(ctx, stage, result.status, `Fix round ${round}: ${result.summary}`, started, { round, details: result.details }));
    return result;
  };

  await run('lint', () => runLint(buildScanContext(ctx, 'lint')));
  await run('sast', () => runSast(buildScanContext(ctx, 'sast')));
  await run('secrets', () => runSecrets(buildScanContext(ctx, 'secrets')));
  await run('deps', () => runDeps(buildScanContext(ctx, 'deps')));
  await run('config', () => runConfig(buildScanContext(ctx, 'config')));
  const tests = await run('unit-tests', () => runTests(buildScanContext(ctx, 'unit-tests')));
  const testDetails = tests.details as { tests?: PipelineCtx['acc']['testResults'] } | undefined;
  if (testDetails?.tests) testResults.push(...testDetails.tests);
  const dast = await run('dast', () => runDast(buildScanContext(ctx, 'dast')));
  const dastDetails = dast.details as { probes?: PipelineCtx['acc']['probeResults'] } | undefined;
  if (dastDetails?.probes) probeResults.push(...dastDetails.probes);

  const findings = finalizeFindings(raw, buildScanContext(ctx, 'fix'), {
    deploymentTarget: ctx.profile?.deployment.target ?? 'local-only',
    decisions: ctx.project.findingDecisions,
    ...(ctx.ruleDecisions ? { ruleDecisions: ctx.ruleDecisions } : {}),
    previousFindings,
    runId: ctx.run.id,
  });
  return { findings, evidence, coverage, testResults, probeResults };
}

export async function runFixLoop(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'fix');

  const provider = ctx.providerFor('fix');
  if (provider.name === 'null') {
    return finishStage(ctx, 'fix', 'skipped', 'AI is not configured, so nothing was fixed automatically.', started, { skippedReason: 'AI is not configured (preview mode)' });
  }
  if (!ctx.design || !ctx.manifest) {
    return finishStage(ctx, 'fix', 'skipped', 'The application was not ready, so nothing could be fixed.', started, { skippedReason: 'no design' });
  }
  if (ctx.settings.maxFixRounds <= 0) {
    return finishStage(ctx, 'fix', 'skipped', 'Automatic fixing is turned off in your settings.', started, { skippedReason: 'maxFixRounds is 0' });
  }

  let candidates = selectCandidates(ctx.acc.findings, ctx.fixFindingIds);
  if (candidates.length === 0) {
    return finishStage(ctx, 'fix', 'skipped', 'Nothing needed fixing.', started, { skippedReason: 'no eligible findings' });
  }

  const fixedIds = new Set<string>();
  const attemptedIds = new Set<string>();
  let round = 0;
  const fixesDir = join(ctx.paths.dir, 'pipeline', ctx.run.id, 'fixes');
  mkdirSync(fixesDir, { recursive: true });

  // Baseline test count and open P1/P2 set, from the scan that ran before the fix stage (not re-accumulated per round).
  let passingTestsBaseline = ctx.acc.testResults.filter((t) => t.ok).length;

  let stoppedForBudget = false;
  while (round < ctx.settings.maxFixRounds && candidates.length > 0) {
    if (remainingBudgetUsd(ctx) < MIN_STAGE_BUDGET_USD) {
      ctx.log('fix', `No further fix round: ${budgetExhaustedText(ctx)}.`);
      stoppedForBudget = true;
      break;
    }
    round++;
    ctx.log('fix', `Fix round ${round}: asking Claude to fix ${candidates.length} finding(s)…`);

    const openP1P2Before = new Set(ctx.acc.findings.filter((f) => isOpen(f) && (f.priority === 'P1' || f.priority === 'P2')).map((f) => f.fingerprint));
    const passingTestsBefore = passingTestsBaseline;
    const protectedBefore = ctx.provenance?.protectedFileHashes ?? computeProtectedFileHashes(ctx.appDir, ctx.manifest);
    const before = snapshotFiles(ctx.appDir);

    const usageBeforeRound = ctx.run.llmUsage;
    const correlationId = `fix-${ctx.run.id}-r${round}`;
    const outcome = await fixFindings(provider, {
      appDir: ctx.appDir,
      design: ctx.design,
      manifest: ctx.manifest,
      findings: candidates,
      round,
      budget: { ...DEFAULT_BUDGETS.fix, maxUsd: Math.min(DEFAULT_BUDGETS.fix.maxUsd, stageBudgetUsd(ctx, 'fix')) },
      runCheck: makeRunCheck(ctx),
      onEvent: (event) => {
        if (event.type === 'security') ctx.log('fix', securityEventLine(event));
        // The event carries this round's running total, so it is added to what was spent before the round.
        if (event.type === 'usage') {
          ctx.run.llmUsage = usageBeforeRound ? mergeUsage(usageBeforeRound, event.usage) : event.usage;
          ctx.bus.spend(ctx.run.llmUsage.estimatedCostUsd, ctx.run.llmUsage.calls);
        }
      },
      abort: ctx.abort.signal,
      runId: ctx.run.id,
      projectId: ctx.project.id,
      correlationId,
      effort: ctx.settings.generationEffort,
    });
    void buildFixBrief; // the agent's own prompt already includes the findings; brief text is informational only here

    ctx.acc.correlationIds.push(correlationId);
    ctx.acc.servedModels.push(...outcome.servedModels);

    const attempts = attributeAttempts(candidates, outcome);
    for (const a of attempts) if (a.attempted) attemptedIds.add(a.findingId);

    // Save one diff per touched file, and a copy per candidate finding whose file was touched.
    for (const rel of outcome.filesTouched) {
      const beforeText = before.get(rel) ?? '';
      const abs = join(ctx.appDir, rel);
      const afterText = existsSync(abs) ? readFileSync(abs, 'utf8') : '';
      const patch = unifiedDiff(rel, beforeText, afterText);
      if (!patch) continue;
      for (const finding of candidates) {
        if (finding.location?.file === rel) writeFileSync(join(fixesDir, `${finding.id}.patch`), patch);
      }
    }

    if (ctx.provenance && outcome.filesTouched.length > 0) {
      ctx.provenance = markGeneratedFiles(ctx.provenance, ctx.appDir, outcome.filesTouched, 'ai-fixed', { correlationId, fixRound: round });
      writeFileSync(join(ctx.appDir, 'securevibe.provenance.json'), `${JSON.stringify(ctx.provenance, null, 2)}\n`);
    }

    if (outcome.filesTouched.length > 0) {
      const refreshed = await refreshDerivedFiles({ appDir: ctx.appDir, projectDir: ctx.paths.dir, runId: ctx.run.id, manifest: ctx.manifest, provenance: ctx.provenance });
      if (refreshed.provenance) ctx.provenance = refreshed.provenance;
      for (const warning of refreshed.warnings) ctx.log('fix', warning);
    }

    const nonRescannedFindings = ctx.acc.findings.filter((f) => f.source === 'ai-review' || f.source === 'external' || f.source === 'typecheck');
    const snapshot = await rescan(ctx, round, ctx.acc.findings);
    const merged = sortFindings([...nonRescannedFindings, ...snapshot.findings]);

    const protectedAfter = computeProtectedFileHashes(ctx.appDir, ctx.manifest);
    // docs/ is regenerated by SecureVibe itself after each round, so it is not part of the regression comparison.
    const withoutDocs = (hashes: Record<string, string>) => JSON.stringify(Object.entries(hashes).filter(([file]) => !file.startsWith('docs/')).sort());
    const protectedUnchanged = withoutDocs(protectedBefore) === withoutDocs(protectedAfter);
    const passingTestsAfter = snapshot.testResults.filter((t) => t.ok).length;
    const newOpenP1P2 = merged.filter((f) => isOpen(f) && (f.priority === 'P1' || f.priority === 'P2') && !openP1P2Before.has(f.fingerprint));
    const noRegressions = protectedUnchanged && passingTestsAfter >= passingTestsBefore && newOpenP1P2.length === 0;

    // Commit this round's results as the current state of the app, whether or not it counts as "fixed".
    ctx.acc.findings = merged;
    ctx.acc.evidence = [...ctx.acc.evidence.filter((e) => e.type === 'ai-review' || e.type === 'design' || e.type === 'manual'), ...snapshot.evidence];
    ctx.acc.coverage = [...ctx.acc.coverage.filter((c) => !snapshot.coverage.some((s) => s.tool === c.tool)), ...snapshot.coverage];
    ctx.acc.testResults = snapshot.testResults;
    ctx.acc.probeResults = snapshot.probeResults;
    passingTestsBaseline = passingTestsAfter;

    const stillOpen: Finding[] = [];
    for (const candidate of candidates) {
      const stillOpenFinding = merged.find((f) => f.fingerprint === candidate.fingerprint && isOpen(f));
      if (noRegressions && !stillOpenFinding) {
        fixedIds.add(candidate.id);
        for (const f of merged) if (f.fingerprint === candidate.fingerprint) f.status = 'fixed';
      } else if (stillOpenFinding) {
        stillOpen.push(stillOpenFinding);
      }
    }
    candidates = stillOpen.slice(0, MAX_CANDIDATES_PER_ROUND);

    if (!noRegressions) ctx.log('fix', `Fix round ${round} introduced a regression (new high-priority finding, fewer passing tests, or a protected file changed); nothing from this round counts as fixed.`);
  }

  ctx.run.fixRounds = round;
  const budgetNote = stoppedForBudget ? ` Stopped early because ${budgetExhaustedText(ctx)}.` : '';
  const summary = `Fix rounds: ${round}. ${fixedIds.size} finding(s) fixed and verified; ${Math.max(attemptedIds.size - fixedIds.size, 0)} attempted but not confirmed fixed.${budgetNote}`;
  return finishStage(ctx, 'fix', fixedIds.size > 0 ? 'passed' : 'warning', summary, started, {
    details: { rounds: round, fixed: [...fixedIds], attempted: [...attemptedIds] },
  });
}
