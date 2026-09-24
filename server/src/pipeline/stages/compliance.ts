/**
 * `compliance`: checks every template control against the code that actually exists (CONTRACTS §1.14/§9.4), then
 * evaluates the SbD checklist, ASVS and AISVS against the combined evidence. `evaluateCompliance` itself
 * (CONTRACTS §9.4's `evaluate`) is owned by another module (`compliance/index.ts`) and is not implemented yet —
 * this stage still assembles the honest, real `EvaluateInput` so it starts working the moment that lands.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { StageResult } from '@shared/pipeline.js';
import { evaluateCompliance, evaluateManifestControls, runAstCheck, type ManifestCheckContext, type RunMeta } from '../../integration.js';
import { runNode } from '../process.js';
import { finishStage, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';
import { saveComplianceInputs, type SavedComplianceInputs } from '../../verification/index.js';
import { humanReviewIsCurrent } from '../human-review.js';
import { summariseCodeCoverage } from '../../compliance/code-coverage.js';
import { DEFAULT_IGNORE, listAppFiles } from '../../scanners/sast/files.js';

async function staleDocFiles(ctx: PipelineCtx): Promise<Set<string>> {
  const stale = new Set<string>();
  if (!existsSync(join(ctx.appDir, 'scripts', 'docs-build.ts'))) return stale;
  const result = await runNode(['--experimental-strip-types', 'scripts/docs-build.ts', '--check'], {
    cwd: ctx.appDir,
    projectDir: ctx.paths.dir,
    runId: ctx.run.id,
    timeoutMs: 60_000,
    abort: ctx.abort.signal,
  });
  for (const line of result.stdout.split('\n')) {
    const m = /^\s*-\s*(docs\/\S+)/.exec(line);
    if (m?.[1]) stale.add(m[1]);
  }
  return stale;
}

export async function runComplianceStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'compliance');
  if (!ctx.design || !ctx.manifest || !ctx.buildSpec) {
    // Without the answers, which rules apply to this app is undecided: the checks that read the code as it is
    // have run and their findings stand; the rules are neither met nor failed, because nobody has said which apply.
    const reason = !ctx.design
      ? 'Which rules apply to this app is not decided yet: the questions about it have not been answered. The checks that read the code as it is have run and their findings stand. Answer the questions and check again, and the compliance report will say which rules apply and whether they are met.'
      : 'There is nothing to evaluate yet.';
    return finishStage(ctx, 'compliance', 'skipped', reason, started, { skippedReason: !ctx.design ? 'questions not answered' : 'no design/manifest' });
  }

  const scanCtx = buildScanContext(ctx, 'compliance');
  const stale = await staleDocFiles(ctx);
  // Manifest `config-value` checks name config checks (config.*) and dependency checks such as deps.sbom-generated,
  // which the deps scanner records as scanner evidence.
  const configResults = ctx.acc.evidence
    .filter((e) => e.type === 'config' || (e.type === 'scanner' && e.ref.startsWith('deps.')))
    .map((e) => ({ id: e.ref, passed: e.passed, detail: e.summary }));

  const manifestCheckCtx: ManifestCheckContext = {
    appDir: ctx.appDir,
    buildSpec: ctx.buildSpec,
    testResults: ctx.acc.testResults,
    probeResults: ctx.acc.probeResults,
    // Code checks are local and quick, so they still run when the build was canceled (only AI and app runs stop).
    astCheck: (name, file) => runAstCheck(name, { ...scanCtx, abort: new AbortController().signal }, file),
    configResults,
    sastFindings: ctx.acc.findings.filter((f) => f.source === 'sast'),
    docsRegenerate: (file) => ({ matches: !stale.has(file), ...(stale.has(file) ? { detail: 'The generated content no longer matches the source of truth.' } : {}) }),
    extraFeatures: ctx.featureFlags,
    runId: ctx.run.id,
    capturedAt: new Date().toISOString(),
  };

  const manifestResults = await evaluateManifestControls(ctx.manifest, manifestCheckCtx);

  // "Was any of this assessed by AI?" is about the review step, which is what produces AI evidence.
  const reviewProvider = ctx.providerFor('ai-review');
  const aiRun = reviewProvider.name !== 'null';
  // The integrity check compares protected files with the hashes recorded at scaffold time; without it (no
  // protected files, as for SecureVibe itself) nothing was verified.
  const protectedCheck = (ctx.manifest?.protectedPaths.length ?? 0) > 0 ? configResults.find((c) => c.id === 'config.protected-files-unchanged') : undefined;
  const runMeta: RunMeta = {
    runId: ctx.run.id,
    mode: ctx.run.mode,
    provider: reviewProvider.name,
    model: reviewProvider.model,
    ...(ctx.provenance ? { generatedAt: ctx.provenance.generatedAt } : {}),
    appDir: ctx.appDir,
    stages: ctx.run.stages,
    coverage: ctx.acc.coverage,
    ...(ctx.provenance ? { provenance: ctx.provenance } : {}),
    ...(ctx.run.approvedAt ? { approvedAt: ctx.run.approvedAt } : {}),
    ...(ctx.run.approvedBy ? { approvedBy: ctx.run.approvedBy } : {}),
    // Facts about AI calls only count when this run could make them.
    ...(aiRun ? { auditLogPresent: ctx.acc.correlationIds.length > 0, screeningPerformed: true } : {}),
    ...(protectedCheck ? { protectedHashesVerified: protectedCheck.passed } : {}),
    ...(ctx.project.escalationAcknowledgedAt ? { escalationAcknowledgedAt: ctx.project.escalationAcknowledgedAt } : {}),
    ...(ctx.provenance ? { sandbox: ctx.provenance.sandbox } : {}),
    incomplete: ctx.run.incomplete,
    fixRounds: ctx.run.fixRounds,
    appName: ctx.profile?.app.name,
    ownerName: ctx.profile?.deployment.owner.name,
    deploymentTarget: ctx.profile?.deployment.target,
    audience: ctx.profile?.users.audience,
  };

  try {
    // Everything automated, kept with the run so people's answers can be added to the reports later for free.
    const automated: SavedComplianceInputs = {
      manifest: ctx.manifest,
      manifestResults,
      findings: ctx.acc.findings,
      evidence: ctx.acc.evidence,
      testResults: ctx.acc.testResults,
      probeResults: ctx.acc.probeResults,
      ...(ctx.aiReviewResult ? { aiReview: ctx.aiReviewResult } : {}),
      runMeta,
    };
    try {
      saveComplianceInputs(ctx.store, ctx.project.id, ctx.run.id, automated);
    } catch (err) {
      ctx.log('compliance', `The results could not be saved for later report refreshes: ${err instanceof Error ? err.message : String(err)}`);
    }
    /**
     * What the scanners could read, worked out from the app folder rather than from any one scanner's tally:
     * a scanner that read nothing would otherwise report nothing, and the gap would be invisible.
     */
    const codeCoverage = summariseCodeCoverage(listAppFiles(ctx.appDir, [...DEFAULT_IGNORE, ...scanCtx.ignore]).map((f) => f.relPath));
    if (!codeCoverage.assessable) ctx.log('compliance', codeCoverage.summary);

    const outcome = await evaluateCompliance({
      ...automated,
      codeCoverage,
      design: ctx.design,
      ...(ctx.profile ? { profile: ctx.profile } : {}),
      attestations: ctx.project.attestations,
      // A review recorded for different code (the app was rebuilt since) no longer counts.
      ...(ctx.project.humanCodeReview && humanReviewIsCurrent(ctx) ? { humanReview: ctx.project.humanCodeReview } : {}),
      knowledge: ctx.knowledge,
      frameworks: ctx.frameworks,
    });
    if (!outcome.ok) {
      return finishStage(ctx, 'compliance', 'skipped', outcome.reason, started, { skippedReason: outcome.reason, details: { manifestControlsChecked: manifestResults.length } });
    }
    ctx.run.compliance = outcome.result;
    return finishStage(ctx, 'compliance', 'passed', outcome.result.overall.headline, started, {
      details: { rating: outcome.result.overall.rating, manifestControlsChecked: manifestResults.length },
    });
  } catch (err) {
    return finishStage(ctx, 'compliance', 'failed', `The compliance evaluation could not run: ${err instanceof Error ? err.message : String(err)}`, started, {
      details: { manifestControlsChecked: manifestResults.length },
    });
  }
}
