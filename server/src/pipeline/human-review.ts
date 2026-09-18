import { existsSync } from 'node:fs';
import { isUploadedApp } from '@shared/project.js';
import { protectedTreeHash } from '../generator/files.js';
import { reviewIsCurrent, SELF_PROJECT_NAME } from '../verification/index.js';
import type { PipelineCtx } from './types.js';

/** True when the owner's recorded code review covers exactly the security-critical files being assessed now. */
export function humanReviewIsCurrent(ctx: PipelineCtx): boolean {
  const review = ctx.project.humanCodeReview;
  if (!review) return false;
  // SecureVibe's own self-assessment has no manifest: its security-critical files are a fixed list.
  if (ctx.project.name === SELF_PROJECT_NAME || isUploadedApp(ctx.project)) return reviewIsCurrent(ctx.project, ctx.store, ctx.config);
  if (!ctx.manifest || !existsSync(ctx.appDir)) return false;
  return review.codeTreeHash === protectedTreeHash(ctx.appDir, ctx.manifest.protectedPaths).hash;
}
