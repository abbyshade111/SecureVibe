#!/usr/bin/env node
/**
 * `npm run eval` — the evaluation harness (docs/CONTRACTS.md "Evaluation harness").
 *
 * Builds each golden app in `evals/golden/*.json` (a saved set of wizard answers) in a scratch workspace, runs every
 * check on it, and compares the outcome with the saved baseline in `evals/baselines/`. Without `--ai` the build uses
 * the template only (free, deterministic enough to run nightly); with `--ai` Claude writes the features too, which
 * spends the owner's credit and is meant for before a release.
 *
 *   --ai               build with Claude (costs money; default is without AI)
 *   --only <name>      one golden app (file name without .json), may repeat
 *   --update           save this run's metrics as the new baseline
 *   --max-usd <n>      spending cap per app with --ai (default: the cap in Settings)
 *   --keep             keep the scratch workspace (its path is printed)
 *
 * Exit code 1 when any case regressed against its baseline or failed to build; a case without a baseline is reported
 * and saved as the baseline only with --update.
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { DesignProfileSchema } from '@shared/profile.js';
import { effectiveAiSettings, loadConfig } from '../config.js';
import { createProvider, deriveDesign, loadFrameworks, loadKnowledge } from '../integration.js';
import { RunBusRegistry, runPipeline } from '../pipeline/index.js';
import { ProjectStore } from '../store/index.js';
import { compareMetrics, metricsOf, summaryLine, type Comparison, type EvalMetrics } from '../eval/metrics.js';

interface CaseResult {
  name: string;
  metrics: EvalMetrics;
  comparison?: Comparison;
  baselineFile: string;
  hadBaseline: boolean;
  /** What went wrong, so a failed case can be understood from the results file without rebuilding it. */
  problems: {
    failedSteps: { step: string; summary: string }[];
    failingTests: { name: string; detail?: string }[];
    openFindings: { severity: string; ruleId: string; title: string; file?: string }[];
  };
}

const PROBLEM_LIMIT = 40;

function problemsOf(run: Awaited<ReturnType<typeof runPipeline>>): CaseResult['problems'] {
  const unitTests = run.stages.find((s) => s.id === 'unit-tests');
  const tests = ((unitTests?.details as { tests?: { name: string; ok: boolean; skipped?: boolean; detail?: string }[] } | undefined)?.tests ?? []).filter(
    (t) => !t.ok && !t.skipped,
  );
  return {
    failedSteps: run.stages.filter((s) => s.status === 'failed').map((s) => ({ step: s.id, summary: s.summary })),
    failingTests: tests.slice(0, PROBLEM_LIMIT).map((t) => ({ name: t.name, ...(t.detail ? { detail: t.detail.slice(0, 400) } : {}) })),
    openFindings: run.findings
      .filter((f) => f.status === 'open')
      .slice(0, PROBLEM_LIMIT)
      .map((f) => ({ severity: f.severity, ruleId: f.ruleId, title: f.title, ...(f.location?.file ? { file: f.location.file } : {}) })),
  };
}

function argValue(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

function argValues(flag: string): string[] {
  const out: string[] = [];
  process.argv.forEach((a, i) => {
    if (a === flag && process.argv[i + 1]) out.push(process.argv[i + 1]!);
  });
  return out;
}

async function main(): Promise<void> {
  const ai = process.argv.includes('--ai');
  const update = process.argv.includes('--update');
  const keep = process.argv.includes('--keep');
  const only = argValues('--only');
  const maxUsdRaw = argValue('--max-usd');
  const maxUsd = maxUsdRaw ? Number(maxUsdRaw) : undefined;
  if (maxUsd !== undefined && !(maxUsd > 0)) throw new Error('--max-usd needs a positive number of US dollars.');
  const mode: EvalMetrics['mode'] = ai ? 'ai' : 'no-ai';

  const config = loadConfig();
  const goldenDir = join(config.paths.repoRoot, 'evals', 'golden');
  const baselineDir = join(config.paths.repoRoot, 'evals', 'baselines');
  const resultsDir = join(config.paths.repoRoot, 'evals', 'results');
  if (!existsSync(goldenDir)) throw new Error(`No golden apps found in ${goldenDir}.`);
  const cases = readdirSync(goldenDir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => basename(f, '.json'))
    .filter((name) => only.length === 0 || only.includes(name))
    .sort();
  if (cases.length === 0) throw new Error(only.length ? `No golden app named ${only.join(', ')}.` : 'No golden apps found.');

  const settings = config.settings.get();
  const aiSettings = effectiveAiSettings(settings);
  const provider = ai ? createProvider({ model: aiSettings.model, reviewEffort: aiSettings.reviewEffort }) : createProvider({ forceProvider: 'null' });
  if (ai && provider.name === 'null') throw new Error('--ai needs an Anthropic API key (see Settings → Your AI service).');
  const spendingCapUsd = maxUsd ?? settings.defaultSpendingCapUsd;

  // Every case builds in its own scratch workspace: nothing here touches the owner's projects.
  const scratchHome = realpathSync(mkdtempSync(join(tmpdir(), 'securevibe-eval-')));
  const store = new ProjectStore(scratchHome);
  const knowledge = loadKnowledge();
  const frameworks = loadFrameworks();

  process.stdout.write(`Evaluation harness: ${cases.length} golden app(s), ${ai ? `with AI (${aiSettings.model}, cap $${spendingCapUsd} each)` : 'without AI'}\n`);
  const results: CaseResult[] = [];
  for (const name of cases) {
    const profile = DesignProfileSchema.parse(JSON.parse(readFileSync(join(goldenDir, `${name}.json`), 'utf8')));
    const project = store.create({ name: profile.app.name, mode: 'guided', profile });
    const design = deriveDesign(profile, { knowledge, frameworks, attestations: project.attestations });
    store.update(project.id, (p) => {
      p.design = design;
      p.profileHash = design.profileHash;
      p.status = 'designed';
    });

    process.stdout.write(`\n▶ ${name}: building…\n`);
    const startedAt = Date.now();
    const run = await runPipeline(
      store.mustGet(project.id),
      { mode: 'full', spendingCapUsd, approvedBy: 'evaluation harness' },
      { store, config: { ...config, paths: { ...config.paths, home: scratchHome, projectsDir: join(scratchHome, 'projects') } }, knowledge, frameworks, provider, busRegistry: new RunBusRegistry() },
    );
    const metrics = metricsOf(run, name, mode);
    if (metrics.durationMs === 0) metrics.durationMs = Date.now() - startedAt;

    const baselineFile = join(baselineDir, `${name}.${mode}.json`);
    const hadBaseline = existsSync(baselineFile);
    const result: CaseResult = { name, metrics, baselineFile, hadBaseline, problems: problemsOf(run) };
    if (hadBaseline) result.comparison = compareMetrics(JSON.parse(readFileSync(baselineFile, 'utf8')) as EvalMetrics, metrics);
    results.push(result);

    process.stdout.write(`  ${summaryLine(metrics)}\n`);
    for (const stage of run.stages) if (stage.status === 'failed') process.stdout.write(`  step ${stage.id} failed: ${stage.summary}\n`);
    if (result.comparison) {
      for (const r of result.comparison.regressions) process.stdout.write(`  ✗ ${r}\n`);
      for (const i of result.comparison.improvements) process.stdout.write(`  ✓ ${i}\n`);
      for (const n of result.comparison.notes) process.stdout.write(`  · ${n}\n`);
      if (!result.comparison.regressions.length && !result.comparison.improvements.length) process.stdout.write('  = same as the baseline\n');
    } else {
      process.stdout.write(update ? '  (no baseline yet: saving this run as the baseline)\n' : '  (no baseline yet: run with --update to save one)\n');
    }
  }

  mkdirSync(resultsDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const resultFile = join(resultsDir, `${stamp}.${mode}.json`);
  writeFileSync(resultFile, `${JSON.stringify({ at: new Date().toISOString(), mode, results }, null, 2)}\n`);

  if (update) {
    mkdirSync(baselineDir, { recursive: true });
    for (const r of results) writeFileSync(r.baselineFile, `${JSON.stringify(r.metrics, null, 2)}\n`);
  }

  const failed = results.filter((r) => r.metrics.status !== 'succeeded');
  const regressed = results.filter((r) => r.comparison?.regressions.length);
  const improved = results.filter((r) => r.comparison?.improvements.length && !r.comparison.regressions.length);
  process.stdout.write('\nSummary\n');
  process.stdout.write(`  ${results.length} golden app(s): ${results.length - failed.length} built, ${failed.length} did not finish\n`);
  process.stdout.write(`  ${regressed.length} regressed, ${improved.length} improved, ${results.filter((r) => !r.hadBaseline).length} without a baseline\n`);
  process.stdout.write(`  Results: ${resultFile}\n`);
  if (update) process.stdout.write(`  Baselines updated in ${baselineDir}\n`);
  if (keep) process.stdout.write(`  Scratch workspace kept: ${scratchHome}\n`);
  else rmSync(scratchHome, { recursive: true, force: true });

  process.exitCode = failed.length || regressed.length ? 1 : 0;
}

main().catch((err) => {
  process.stderr.write(`eval failed: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`);
  process.exitCode = 1;
});
