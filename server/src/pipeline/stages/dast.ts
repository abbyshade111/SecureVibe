/**
 * `dast`: starts the generated app privately on 127.0.0.1 and probes it. Skipped when `install` did not succeed
 * (the app cannot start without its packages). The raw probe results are saved to `pipeline/<runId>/dast/probes.json`
 * for the report's "how we checked" appendix.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { StageResult } from '@shared/pipeline.js';
import { runDast } from '../../integration.js';
import { absorbScanResult, installFailed, skipStage, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runDastStage(ctx: PipelineCtx): Promise<StageResult> {
  if (installFailed(ctx)) {
    return skipStage(ctx, 'dast', 'The packages did not install, so the running application could not be tested.');
  }
  const started = startStage(ctx, 'dast');
  const result = await runDast(buildScanContext(ctx, 'dast'), { ...(ctx.dastAuth ? { auth: ctx.dastAuth } : {}), ...(ctx.dastExtra ?? {}) });
  const stage = absorbScanResult(ctx, 'dast', started, result);

  const details = result.details as { probes?: unknown } | undefined;
  if (details?.probes) {
    const dir = join(ctx.paths.dir, 'pipeline', ctx.run.id, 'dast');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'probes.json'), `${JSON.stringify(details.probes, null, 2)}\n`);
    ctx.acc.probeResults.push(...(details.probes as PipelineCtx['acc']['probeResults']));
  }
  return stage;
}
