/**
 * `install`: `npm ci --ignore-scripts --prefer-offline` inside the generated app, unless the scaffold stage's
 * node_modules fast path already copied a matching install. A failure here does not stop the pipeline — it only
 * skips the stages that need a working install (CONTRACTS §9.5): typecheck, unit-tests, dast.
 */
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { StageResult } from '@shared/pipeline.js';
import { runNpm } from '../process.js';
import { finishStage, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';

export const INSTALL_TIMEOUT_MS = 10 * 60_000;

export async function runInstall(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'install');

  if (existsSync(join(ctx.appDir, 'node_modules', '.package-lock.json')) || existsSync(join(ctx.appDir, 'node_modules', 'express'))) {
    return finishStage(ctx, 'install', 'skipped', 'The packages were already installed from a matching, previously tested set.', started, {
      skippedReason: 'node_modules fast path',
    });
  }

  const result = await runNpm(['ci', '--ignore-scripts', '--prefer-offline', '--no-audit', '--no-fund'], {
    cwd: ctx.appDir,
    projectDir: ctx.paths.dir,
    runId: ctx.run.id,
    timeoutMs: INSTALL_TIMEOUT_MS,
    abort: ctx.abort.signal,
  });

  if (result.code === 0) {
    return finishStage(ctx, 'install', 'passed', 'The application\'s packages are installed.', started);
  }

  const detail = (result.stderr || result.stdout).trim().slice(-1000);
  return finishStage(ctx, 'install', 'failed', `The packages could not be installed. The checks that need a working install will be skipped. ${detail ? `Details: ${detail}` : ''}`, started);
}
