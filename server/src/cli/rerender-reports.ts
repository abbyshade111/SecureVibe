#!/usr/bin/env node
/**
 * `npm run -w server reports:rerender -- <projectId> [runId]`: rebuilds a run's reports from the results saved
 * with that run (after a SecureVibe update changed how reports look). Nothing is checked again and no AI is used;
 * the numbers in the reports are exactly the saved ones.
 */
import { loadFrameworks, loadKnowledge, renderReports } from '../integration.js';
import { loadConfig } from '../config.js';
import { ProjectStore } from '../store/index.js';

async function main(): Promise<void> {
  const [projectId, requestedRunId] = process.argv.slice(2);
  if (!projectId) {
    process.stderr.write('Usage: reports:rerender -- <projectId> [runId]\n');
    process.exitCode = 1;
    return;
  }
  const config = loadConfig();
  const store = new ProjectStore(config.paths.home);
  const project = store.mustGet(projectId);
  const runId = requestedRunId ?? project.lastRunId;
  const run = runId ? store.readRun(project.id, runId) : undefined;
  if (!run) throw new Error(`No saved run ${runId ?? '(none)'} for project ${project.id}.`);
  if (!project.design) throw new Error('This project has no design, so its reports cannot be rebuilt.');

  const outcome = await renderReports({
    project,
    run,
    design: project.design,
    ...(run.provenance ? { provenance: run.provenance } : {}),
    findings: run.findings,
    ...(run.compliance ? { compliance: run.compliance } : {}),
    coverage: run.coverage,
    ...(run.llmUsage ? { llmUsage: run.llmUsage } : {}),
    stages: run.stages,
    outDir: store.reportsDir(project.id, run.id),
    appDir: store.paths(project.id).appDir,
    knowledge: loadKnowledge(),
    frameworks: loadFrameworks(),
    securevibeVersion: config.version,
    pdfPageSize: config.settings.get().pdfPageSize,
  });
  if (!outcome.ok) throw new Error(outcome.reason);
  run.artifacts = outcome.result.artifacts;
  await store.writeRun(run);
  process.stdout.write(`Rebuilt ${run.artifacts.length} report file(s) for run ${run.id} in ${store.reportsDir(project.id, run.id)}\n`);
}

main().catch((err) => {
  process.stderr.write(`reports:rerender failed: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exitCode = 1;
});
