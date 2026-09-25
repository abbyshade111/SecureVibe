/**
 * `external`: semgrep / gitleaks / trivy / osv-scanner, when installed on this computer, plus nano-analyzer when
 * the owner has switched it on in Settings (it costs money and sends the code to an AI service, so it never runs
 * by itself), plus the virus scanner for an app the owner uploaded.
 */
import type { StageResult } from '@shared/pipeline.js';
import { isUploadedApp } from '@shared/project.js';
import { runExternal } from '../../integration.js';
import { nanoOptionsFor } from '../../scanners/external/nano-analyzer.js';
import { absorbScanResult, startStage } from '../stage-helpers.js';
import { buildScanContext, type PipelineCtx } from '../types.js';

export async function runExternalStage(ctx: PipelineCtx): Promise<StageResult> {
  const started = startStage(ctx, 'external');
  // ADR-011: for an app the owner handed us, asking whether any of these files is known-bad is part of the
  // ordinary check rather than something behind a switch. For an app SecureVibe wrote, it is the Settings switch.
  const result = await runExternal(buildScanContext(ctx, 'external'), {
    nano: nanoOptionsFor(ctx.settings),
    clamav: { enabled: isUploadedApp(ctx.project) || ctx.settings.scanBuiltAppsForMalware === true },
  });
  return absorbScanResult(ctx, 'external', started, result);
}
