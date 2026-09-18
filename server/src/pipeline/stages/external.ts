/**
 * `external`: semgrep / gitleaks / trivy / osv-scanner, when installed on this computer, plus nano-analyzer when
 * the owner has switched it on in Settings (it costs money and sends the code to an AI service, so it never runs
 * by itself).
 */
import type { StageResult } from '@shared/pipeline.js';
import { runExternal } from '../../integration.js';
import { nanoOptionsFor } from '../../scanners/external/nano-analyzer.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runExternalStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'external');
  const result = await runExternal(buildScanContext(ctx, 'external'), { nano: nanoOptionsFor(ctx.settings) });
  return absorbScanResult(ctx, 'external', started, result);
}
