/**
 * Reviewing again only what changed: which of the last check's AI verdicts may stand, and which must be formed
 * afresh. The rule that matters is that a verdict is only kept when the file it cites is byte-for-byte the same.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { Evidence } from '@shared/compliance.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { carryForwardReview } from '../../src/pipeline/diff-aware.js';

const dirs: string[] = [];
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop()!, { recursive: true, force: true });
});

function appWith(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'sv-diff-aware-'));
  dirs.push(dir);
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  return dir;
}

const sha = (text: string): string => createHash('sha256').update(text).digest('hex');

function aiEvidence(requirement: string, file: string, citationVerified = true, citedFiles?: string[]): Evidence {
  return {
    id: 'E-0001',
    type: 'ai-review',
    tier: 'weak',
    ref: `ai-review:${requirement}`,
    summary: 'The AI read this and thought it holds.',
    passed: true,
    capturedAt: '2026-09-17T10:00:00.000Z',
    location: { file, line: 3 },
    aiReview: { model: 'claude-opus-5', promptHash: 'h', confidence: 'medium', citationVerified, ...(citedFiles ? { citedFiles } : {}) },
  };
}

function previousRun(evidence: Evidence[], hashes: Record<string, string>, designProfileHash = 'design-1'): PipelineRun {
  return {
    id: 'r_20260917100000_aaaaaa',
    projectId: 'p_1',
    mode: 'full',
    status: 'succeeded',
    startedAt: '2026-09-17T10:00:00.000Z',
    stages: [],
    findings: [],
    coverage: [],
    provenance: { designProfileHash, protectedFileHashes: hashes, generatedFiles: [] },
    compliance: {
      asvs: { summary: {}, results: evidence.map((e, i) => ({ id: `V${i + 1}.1.1`, evidence: [e] })) },
    },
  } as unknown as PipelineRun;
}

describe('reviewing again only what changed', () => {
  it('keeps a verdict when the file it cites has not changed', () => {
    const code = 'export const a = 1;\n';
    const appDir = appWith({ 'src/app.ts': code });
    const previous = previousRun([aiEvidence('V6.1.1', 'src/app.ts')], { 'src/app.ts': sha(code) });

    const carried = carryForwardReview(previous, appDir, 'design-1');
    expect([...carried.skip]).toEqual(['V6.1.1']);
    expect(carried.evidence[0]!.summary).toMatch(/carried over from the check on 2026-09-17/);
    // The verdict stays what it was: an AI opinion, with the date it was really formed.
    expect(carried.evidence[0]!.tier).toBe('weak');
    expect(carried.evidence[0]!.capturedAt).toBe('2026-09-17T10:00:00.000Z');
    expect(carried.note).toMatch(/has not changed since/);
    expect(carried.note).toMatch(/every file/i);
  });

  it('reviews again when the file has changed at all', () => {
    const appDir = appWith({ 'src/app.ts': 'export const a = 2;\n' });
    const previous = previousRun([aiEvidence('V6.1.1', 'src/app.ts')], { 'src/app.ts': sha('export const a = 1;\n') });
    expect(carryForwardReview(previous, appDir, 'design-1').skip.size).toBe(0);
  });

  it('reviews again when any file the verdict read has changed, not just the one it points at', () => {
    // An assessment can cite several files; only the first is shown as its location. Comparing that one alone
    // carried verdicts across rebuilds that had rewritten the others, while telling the owner the code the
    // verdict rests on was untouched. It weakened the only check that costs money.
    const appDir = appWith({ 'src/a.ts': 'first', 'src/b.ts': 'second (rewritten)' });
    const previous = previousRun([aiEvidence('V1.1.1', 'src/a.ts', true, ['src/a.ts', 'src/b.ts'])], {
      'src/a.ts': sha('first'),
      'src/b.ts': sha('second'),
    });
    expect(carryForwardReview(previous, appDir, 'design-1').skip.size).toBe(0);
  });

  it('carries the verdict when every file it read is untouched, and says how many', () => {
    const appDir = appWith({ 'src/a.ts': 'first', 'src/b.ts': 'second' });
    const previous = previousRun([aiEvidence('V1.1.1', 'src/a.ts', true, ['src/a.ts', 'src/b.ts'])], {
      'src/a.ts': sha('first'),
      'src/b.ts': sha('second'),
    });
    const carried = carryForwardReview(previous, appDir, 'design-1');
    expect(carried.skip.has('V1.1.1')).toBe(true);
    expect(carried.evidence[0]!.summary).toMatch(/all 2 files it read/);
  });

  it('reviews again when the citation was never verified, or there is no file to check', () => {
    const code = 'export const a = 1;\n';
    const appDir = appWith({ 'src/app.ts': code });
    const hashes = { 'src/app.ts': sha(code) };
    expect(carryForwardReview(previousRun([aiEvidence('V6.1.1', 'src/app.ts', false)], hashes), appDir, 'design-1').skip.size).toBe(0);

    const noFile = aiEvidence('V6.1.1', 'src/app.ts');
    delete (noFile as { location?: unknown }).location;
    expect(carryForwardReview(previousRun([noFile], hashes), appDir, 'design-1').skip.size).toBe(0);
  });

  it('carries nothing across a change of answers, because the same code can mean something different', () => {
    const code = 'export const a = 1;\n';
    const appDir = appWith({ 'src/app.ts': code });
    const previous = previousRun([aiEvidence('V6.1.1', 'src/app.ts')], { 'src/app.ts': sha(code) }, 'design-1');
    expect(carryForwardReview(previous, appDir, 'design-2').skip.size).toBe(0);
  });

  it('carries nothing when there is no earlier check to carry from', () => {
    expect(carryForwardReview(undefined, appWith({}), 'design-1').skip.size).toBe(0);
  });
});
