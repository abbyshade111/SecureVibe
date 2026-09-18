/** `typecheck`: `tsc -p tsconfig.json --noEmit` inside the generated app. Skipped when `install` did not succeed. */
import type { StageResult } from '@shared/pipeline.js';
import { runTypecheckCheck } from '../checks.js';
import { appendStageLog } from '../persist.js';
import { finishStage, installFailed, skipStage, startStage } from '../stage-helpers.js';
import type { PipelineCtx } from '../types.js';

export async function runTypecheck(ctx: PipelineCtx): Promise<StageResult> {
  if (installFailed(ctx)) {
    return skipStage(ctx, 'typecheck', 'The packages did not install, so the code could not be type-checked.');
  }
  const started = startStage(ctx, 'typecheck');
  const outcome = await runTypecheckCheck(ctx);
  if (outcome.output) appendStageLog(ctx.store, ctx.project.id, ctx.run.id, 'typecheck', outcome.output);
  if (outcome.skippedReason) return finishStage(ctx, 'typecheck', 'skipped', outcome.skippedReason, started, { skippedReason: outcome.skippedReason });
  return finishStage(
    ctx,
    'typecheck',
    outcome.ok ? 'passed' : 'failed',
    outcome.ok ? 'The code is consistent and type-safe.' : 'The code does not compile cleanly. See the log for details.',
    started,
    { details: { output: outcome.output } },
  );
}
