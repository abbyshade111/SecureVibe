import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { protectedTreeHash } from '../../src/generator/files.js';
import { humanReviewIsCurrent } from '../../src/pipeline/human-review.js';
import type { PipelineCtx } from '../../src/pipeline/types.js';

const appDir = mkdtempSync(join(tmpdir(), 'sv-review-'));
afterAll(() => rmSync(appDir, { recursive: true, force: true }));

function ctxWith(codeTreeHash: string): PipelineCtx {
  return {
    appDir,
    manifest: { protectedPaths: ['src/security/**'] },
    project: { humanCodeReview: { reviewedBy: 'Sam', reviewedAt: '2026-09-17T00:00:00.000Z', filesReviewed: [], codeTreeHash } },
  } as unknown as PipelineCtx;
}

describe('human code review', () => {
  it('counts only while the reviewed security-critical files are unchanged', () => {
    mkdirSync(join(appDir, 'src', 'security'), { recursive: true });
    writeFileSync(join(appDir, 'src', 'security', 'auth.ts'), 'export const a = 1;\n');
    writeFileSync(join(appDir, 'src', 'feature.ts'), 'export const b = 1;\n');
    const reviewed = protectedTreeHash(appDir, ['src/security/**']);
    expect(reviewed.files).toEqual(['src/security/auth.ts']);
    expect(humanReviewIsCurrent(ctxWith(reviewed.hash))).toBe(true);

    // Other files may change; the review still covers the security-critical ones.
    writeFileSync(join(appDir, 'src', 'feature.ts'), 'export const b = 2;\n');
    expect(humanReviewIsCurrent(ctxWith(reviewed.hash))).toBe(true);

    writeFileSync(join(appDir, 'src', 'security', 'auth.ts'), 'export const a = 2;\n');
    expect(humanReviewIsCurrent(ctxWith(reviewed.hash))).toBe(false);
  });
});
