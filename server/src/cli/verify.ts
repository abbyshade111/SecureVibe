#!/usr/bin/env node
/**
 * `tsx src/cli/verify.ts <appDir> [profile.json]`: runs the verify-only pipeline (every check except
 * design-freeze/scaffold/generate/fix) against an application that already exists, and writes the reports next
 * to it in `<appDir>/../securevibe-verify-reports/`.
 */
import { existsSync, readFileSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import { DesignProfileSchema } from '@shared/profile.js';
import { deriveDesign, loadFrameworks, loadKnowledge, createProvider } from '../integration.js';
import { loadConfig } from '../config.js';
import { RunBusRegistry, runPipeline } from '../pipeline/index.js';
import { ProjectStore } from '../store/index.js';

async function main(): Promise<void> {
  const [, , appDirArg, profileArg] = process.argv;
  if (!appDirArg) {
    process.stderr.write('Usage: tsx src/cli/verify.ts <appDir> [profile.json]\n');
    process.exitCode = 1;
    return;
  }
  const appDir = resolve(appDirArg);
  if (!existsSync(appDir)) {
    process.stderr.write(`${appDir} does not exist.\n`);
    process.exitCode = 1;
    return;
  }
  const profileFile = profileArg ? resolve(profileArg) : resolve(appDir, '..', 'profile.json');
  if (!existsSync(profileFile)) {
    process.stderr.write(`No profile.json found (looked at ${profileFile}). Pass one explicitly: tsx src/cli/verify.ts <appDir> <profile.json>\n`);
    process.exitCode = 1;
    return;
  }
  const profile = DesignProfileSchema.parse(JSON.parse(readFileSync(profileFile, 'utf8')));

  const config = loadConfig();
  const store = new ProjectStore(config.paths.home);
  const knowledge = loadKnowledge();
  const frameworks = loadFrameworks();

  const project = store.create({ name: `Verify: ${basename(appDir)}`, mode: 'quick', profile });
  project.design = deriveDesign(profile, { knowledge, frameworks });
  project.profileHash = project.design.profileHash;
  store.save(project);

  process.stdout.write(`Verifying ${appDir} against ${profileFile}…\n`);
  const run = await runPipeline(
    project,
    { mode: 'verify-only', spendingCapUsd: config.settings.get().defaultSpendingCapUsd, appDir },
    { store, config, knowledge, frameworks, provider: createProvider({}), busRegistry: new RunBusRegistry() },
  );

  process.stdout.write(`\nRun ${run.id}: ${run.status}\n`);
  for (const stage of run.stages) process.stdout.write(`  ${stage.id.padEnd(14)} ${stage.status.padEnd(9)} ${stage.summary}\n`);
  const reportsDir = store.reportsDir(project.id, run.id);
  process.stdout.write(`\nReports written to ${reportsDir}\n`);
  void dirname; // reserved for a future --out flag
  process.exitCode = run.status === 'succeeded' ? 0 : 1;
}

main().catch((err) => {
  process.stderr.write(`verify failed: ${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exitCode = 1;
});
