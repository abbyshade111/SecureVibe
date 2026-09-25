/**
 * `reports`: renders the compliance report, security report, overview and the rest (CONTRACTS §9.6/§12) via the
 * `reports/` module. Until that module exists, a minimal JSON snapshot is written instead so a run still leaves
 * something behind to look at and download.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { ArtifactRef, StageResult } from '@shared/pipeline.js';
import { renderReports } from '../../integration.js';
import { renderReportsWithoutAnswers } from '../../reports/index.js';
import { finishStage, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';

function fallbackArtifacts(ctx: PipelineCtx, outDir: string): ArtifactRef[] {
  const relDir = `reports/${ctx.run.id}`;
  writeFileSync(join(outDir, 'run-summary.json'), `${JSON.stringify(ctx.run, null, 2)}\n`);
  const artifacts: ArtifactRef[] = [
    {
      name: 'run-summary.json',
      path: `${relDir}/run-summary.json`,
      kind: 'json',
      format: 'json',
      description: 'The full technical result of this build. Full-page reports are not built into this copy of SecureVibe yet.',
    },
  ];
  if (ctx.provenance) {
    writeFileSync(join(outDir, 'provenance.json'), `${JSON.stringify(ctx.provenance, null, 2)}\n`);
    artifacts.push({ name: 'provenance.json', path: `${relDir}/provenance.json`, kind: 'provenance', format: 'json', description: 'Where every file in this build came from.' });
  }
  return artifacts;
}

export async function runReportsStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'reports');
  const outDir = ctx.store.reportsDir(ctx.project.id, ctx.run.id);
  mkdirSync(outDir, { recursive: true });

  if (!ctx.design) {
    // A check before the questions were answered: every report that does not depend on the answers is written in
    // full (security report, SARIF, run log, provenance, bill of materials); the compliance report and the design
    // document need the answers, and the overview says so.
    try {
      const outcome = await renderReportsWithoutAnswers({
        project: ctx.project,
        run: ctx.run,
        ...(ctx.manifest ? { manifest: ctx.manifest } : {}),
        ...(ctx.provenance ? { provenance: ctx.provenance } : {}),
        findings: ctx.acc.findings,
        coverage: ctx.acc.coverage,
        ...(ctx.run.llmUsage ? { llmUsage: ctx.run.llmUsage } : {}),
        stages: ctx.run.stages,
        outDir,
        appDir: ctx.appDir,
        knowledge: ctx.knowledge,
        frameworks: ctx.frameworks,
        securevibeVersion: ctx.config.version,
        pdfPageSize: ctx.settings.pdfPageSize,
      });
      ctx.run.artifacts = outcome.artifacts;
      return finishStage(
        ctx,
        'reports',
        'passed',
        'The security report, the findings file and the run record are ready. There is no compliance report yet: which rules apply is decided by the questions about this app, which have not been answered.',
        started,
        { details: { artifacts: outcome.artifacts.length } },
      );
    } catch (err) {
      ctx.run.artifacts = fallbackArtifacts(ctx, outDir);
      return finishStage(ctx, 'reports', 'warning', `The reports could not be written (${err instanceof Error ? err.message : String(err)}). A raw summary was saved instead.`, started);
    }
  }

  const outcome = await renderReports({
    project: ctx.project,
    run: ctx.run,
    design: ctx.design,
    ...(ctx.manifest ? { manifest: ctx.manifest } : {}),
    ...(ctx.provenance ? { provenance: ctx.provenance } : {}),
    findings: ctx.acc.findings,
    ...(ctx.run.compliance ? { compliance: ctx.run.compliance } : {}),
    coverage: ctx.acc.coverage,
    ...(ctx.run.llmUsage ? { llmUsage: ctx.run.llmUsage } : {}),
    stages: ctx.run.stages,
    outDir,
    appDir: ctx.appDir,
    knowledge: ctx.knowledge,
    frameworks: ctx.frameworks,
    securevibeVersion: ctx.config.version,
    pdfPageSize: ctx.settings.pdfPageSize,
  });

  if (!outcome.ok) {
    ctx.run.artifacts = fallbackArtifacts(ctx, outDir);
    return finishStage(ctx, 'reports', 'warning', `${outcome.reason} A raw summary was saved instead.`, started, { skippedReason: outcome.reason });
  }

  ctx.run.artifacts = outcome.result.artifacts;
  return finishStage(ctx, 'reports', 'passed', 'Your reports are ready.', started, { details: { artifacts: outcome.result.artifacts.length } });
}
