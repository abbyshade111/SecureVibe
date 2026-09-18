/** `deps`: `npm audit`, lockfile checks, license inventory and the CycloneDX SBOM. Degrades honestly when offline. */
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import type { StageResult } from '@shared/pipeline.js';
import { runDeps } from '../../integration.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runDepsStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'deps');
  const reportsDir = ctx.store.reportsDir(ctx.project.id, ctx.run.id);
  mkdirSync(reportsDir, { recursive: true });
  const sbomOutFile = join(reportsDir, 'sbom.cdx.json');
  const result = await runDeps(buildScanContext(ctx, 'deps'), { sbomOutFile });
  return absorbScanResult(ctx, 'deps', started, result);
}
