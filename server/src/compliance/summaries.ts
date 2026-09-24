/**
 * Standard-level summaries (CONTRACTS §9.4, DESIGN §13.1): counts, coverage percentages and the plain three-way
 * rating shown at the top of the compliance report. Never a single color — always the four headline numbers.
 */
import type { ChapterSummary, RequirementResult, StandardId, StandardSummary } from '@shared/compliance.js';
import { emptyCounts } from '@shared/compliance.js';
import type { Finding } from '@shared/findings.js';
import { isOpen } from '@shared/findings.js';

export function round1(n: number): number {
  return Math.round(n * 10) / 10;
}

/**
 * The rating and, in the same breath, where it comes from. Two scoreboards feed it: the requirement count for a
 * standard (ASVS, AISVS) and the Secure by Design checklist, where one unmet critical control is enough for
 * "At risk" whatever the count says. An owner reading "At risk" above "107 of 159 verified passing" sees a
 * contradiction unless the reason names its source, so every reason does.
 *
 * `source` names the count the rating is about ("ASVS", "ASVS and AISVS"); `criticalNo` lists unmet critical
 * Secure by Design controls, which only the overall rating takes into account.
 */
export function computeRating(
  counts: ReturnType<typeof emptyCounts>,
  applicableCount: number,
  hasP1Fail: boolean,
  source = 'requirement',
  criticalNo: string[] = [],
): { rating: StandardSummary['rating']; ratingReason: string } {
  const verifiedPassPercent = applicableCount > 0 ? (counts.pass / applicableCount) * 100 : 100;
  if (hasP1Fail) {
    return {
      rating: 'at-risk',
      ratingReason: 'At risk because an urgent (P1) security finding is linked to a failing requirement. That comes from what was found, not from the count.',
    };
  }
  if (criticalNo.length > 0) {
    const n = criticalNo.length;
    return {
      rating: 'at-risk',
      ratingReason: `At risk comes from Secure by Design: ${n === 1 ? 'a critical control' : `${n} critical controls`} (${criticalNo.join(', ')}) ${n === 1 ? 'is' : 'are'} not met. The ${source} count is a different measure, and a good score there does not lift a critical control.`,
    };
  }
  if (counts.fail === 0 && verifiedPassPercent >= 60) {
    return { rating: 'good', ratingReason: `Good comes from the ${source} count: ${round1(verifiedPassPercent)}% of applicable requirements are verified passing, and nothing failed.` };
  }
  if (counts.fail > 0) {
    return { rating: 'needs-attention', ratingReason: `Needs attention comes from the ${source} count: ${counts.fail} requirement(s) failed and need a developer's attention.` };
  }
  return {
    rating: 'needs-attention',
    ratingReason: `Needs attention comes from the ${source} count: only ${round1(verifiedPassPercent)}% of applicable requirements are verified passing; the rest need automated evidence or a manual check.`,
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
  const { rating, ratingReason } = computeRating(counts, applicableCount, hasP1Fail, name);

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
