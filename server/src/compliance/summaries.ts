/**
 * Standard-level summaries (CONTRACTS §9.4, DESIGN §13.1): counts, coverage percentages and the plain three-way
 * rating shown at the top of the compliance report. Never a single colour — always the four headline numbers.
 */
import type { ChapterSummary, RequirementResult, StandardId, StandardSummary } from '@shared/compliance.js';
import { emptyCounts } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import { isOpen } from '@shared/findings.js';

export function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

export function computeRating(
  counts: ReturnType<typeof emptyCounts>,
  applicableCount: number,
  hasP1Fail: boolean,
  extraAtRisk = false,
): { rating: StandardSummary['rating']; ratingReason: string } {
  const verifiedPassPercent = applicableCount > 0 ? (counts.pass / applicableCount) * 100 : 100;
  if (hasP1Fail || extraAtRisk) {
    return {
      rating: 'at-risk',
      ratingReason: hasP1Fail
        ? 'At least one failing requirement is linked to an urgent (P1) security finding.'
        : 'A critical Secure by Design control is not met.',
    };
  }
  if (counts.fail === 0 && verifiedPassPercent >= 60) {
    return { rating: 'good', ratingReason: `${round1(verifiedPassPercent)}% of applicable requirements are verified passing, and nothing failed.` };
  }
  if (counts.fail > 0) {
    return { rating: 'needs-attention', ratingReason: `${counts.fail} requirement(s) failed and need a developer's attention.` };
  }
  return {
    rating: 'needs-attention',
    ratingReason: `Only ${round1(verifiedPassPercent)}% of applicable requirements are verified passing; the rest need automated evidence or a manual check.`,
  };
}

export function summarizeStandard(
  standard: StandardId,
  name: string,
  version: string,
  targetLevel: number,
  targetLevelRule: string,
  results: RequirementResult[],
  findings: Finding[],
): StandardSummary {
  const counts = emptyCounts();
  const chapterMap = new Map<string, { name: string; counts: ReturnType<typeof emptyCounts> }>();
  let applicableCount = 0;
  let automatableCount = 0;

  for (const r of results) {
    counts[r.status]++;
    const notCounted = r.status === 'not-applicable' || r.status === 'out-of-level';
    if (!notCounted) {
      applicableCount++;
      if (r.verificationClass === 'automatable') automatableCount++;
    }
    if (!chapterMap.has(r.chapterId)) chapterMap.set(r.chapterId, { name: r.chapterName, counts: emptyCounts() });
    chapterMap.get(r.chapterId)!.counts[r.status]++;
  }

  const byChapter: ChapterSummary[] = [...chapterMap.entries()]
    .sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
    .map(([id, v]) => ({ id, name: v.name, counts: v.counts }));

  const verifiedPassPercent = applicableCount > 0 ? round1((counts.pass / applicableCount) * 100) : 0;
  const automatedCoveragePercent = applicableCount > 0 ? round1(((counts.pass + counts.fail + counts.partial) / applicableCount) * 100) : 0;

  const failingIds = new Set(results.filter((r) => r.status === 'fail').flatMap((r) => r.findingIds));
  const hasP1Fail = findings.some((f) => failingIds.has(f.id) && isOpen(f) && f.priority === 'P1');
  const { rating, ratingReason } = computeRating(counts, applicableCount, hasP1Fail);

  return {
    standard,
    name,
    version,
    targetLevel,
    targetLevelRule,
    counts,
    byChapter,
    applicableCount,
    verifiedPassPercent,
    automatedCoveragePercent,
    automatableCount,
    rating,
    ratingReason,
  };
}
