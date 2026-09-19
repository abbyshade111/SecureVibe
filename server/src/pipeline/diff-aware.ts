/**
 * Reviewing again only what changed.
 *
 * The AI review is the one expensive check: every other check is a program reading files and costs nothing to run
 * again. On a rebuild, most of an app is byte-for-byte what it was, so paying to have the same lines read again
 * buys nothing. This works out which of the previous run's AI assessments still describe the code on disk, and
 * hands them forward so the review can spend its money on what actually changed.
 *
 * The rules are deliberately strict, because the alternative is a report that claims something was checked when it
 * was not:
 *
 *  - Only an assessment that cited a file is carried. No citation, no way to tell whether it still applies.
 *  - Only when that file is byte-identical to the file the earlier run assessed, by hash.
 *  - Only when the answers behind the design have not changed, because a different design can mean the same file
 *    means something different.
 *  - Nothing is upgraded on the way: an AI assessment stays an AI assessment, and it keeps the run id and the date
 *    it was really made, so the report shows when each verdict was formed.
 *
 * Everything that is not carried is reviewed again. When in doubt, it is reviewed again.
 */
import { join } from 'node:path';
import type { Evidence } from '@shared/compliance.js';
import type { PipelineRun } from '@shared/pipeline.js';
import { sha256File } from '../scanners/sast/files.js';

export interface CarriedReview {
  /** Requirement ids the review may leave out this time, because a previous verdict still stands. */
  skip: Set<string>;
  /** The previous assessments, marked as carried over, to be counted as this run's evidence. */
  evidence: Evidence[];
  /** One plain sentence for the log and the stage summary. */
  note: string;
}

export const NOTHING_CARRIED: CarriedReview = { skip: new Set(), evidence: [], note: '' };

/** The file hashes the earlier run recorded: what it actually read when it formed its verdicts. */
function hashesFrom(previous: PipelineRun): Map<string, string> {
  const out = new Map<string, string>();
  for (const [path, sha] of Object.entries(previous.provenance?.protectedFileHashes ?? {})) out.set(path, sha);
  // Generated files come second: where a file is both, what the agent last wrote is what was assessed.
  for (const file of previous.provenance?.generatedFiles ?? []) out.set(file.path, file.sha256);
  return out;
}

/** The requirement an AI-review evidence item is about ("ai-review:V8.2.2" → "V8.2.2"). */
export function requirementOf(evidence: Evidence): string | undefined {
  const match = /^ai-review:([A-Za-z0-9.]+)$/.exec(evidence.ref);
  return match?.[1];
}

/**
 * What may be carried from the previous run into this one. `appDir` is the app as it is now; a file is unchanged
 * only when its hash matches what the previous run recorded for it.
 */
export function carryForwardReview(previous: PipelineRun | undefined, appDir: string, designProfileHash: string | undefined): CarriedReview {
  if (!previous?.compliance || !previous.provenance) return NOTHING_CARRIED;
  // A changed design can give the same code a different meaning, so nothing is carried across one.
  if (!designProfileHash || previous.provenance.designProfileHash !== designProfileHash) return NOTHING_CARRIED;

  const recorded = hashesFrom(previous);
  const unchanged = new Map<string, boolean>();
  const isUnchanged = (path: string): boolean => {
    const cached = unchanged.get(path);
    if (cached !== undefined) return cached;
    const before = recorded.get(path);
    const now = before ? sha256File(join(appDir, ...path.split('/'))) : undefined;
    const same = Boolean(before && now && before === now);
    unchanged.set(path, same);
    return same;
  };

  const skip = new Set<string>();
  const evidence: Evidence[] = [];
  // Evidence lives on each requirement's result, in every standard the run assessed.
  const results = [
    ...previous.compliance.asvs.results,
    ...(previous.compliance.aisvs?.results ?? []),
    ...(previous.compliance.appendixC?.results ?? []),
  ];
  for (const result of results) {
    for (const item of result.evidence) {
      if (item.type !== 'ai-review') continue;
      const requirement = requirementOf(item) ?? result.id;
      const file = item.location?.file;
      // No citation, or one that was never verified: there is nothing to stand on, so it is reviewed again.
      if (!file || item.aiReview?.citationVerified !== true) continue;
      // Every file the assessment cited has to be unchanged, not merely the one shown as its location. A verdict
      // formed by reading three files says nothing about the app once two of them have been rewritten, and
      // carrying it forward would quietly weaken the one check the owner pays for. Older runs recorded only the
      // location, so fall back to it: those are carried on the same terms as before rather than being discarded.
      const cited = item.aiReview.citedFiles?.length ? item.aiReview.citedFiles : [file];
      if (!cited.every((f) => isUnchanged(f))) continue;
      skip.add(requirement);
      evidence.push({
        ...item,
        // The verdict keeps the run and the date it was really formed; only the wording says it was carried.
        // Names the one file that was actually compared, rather than implying the whole verdict was re-checked.
        // An assessment can cite several files and only the first is recorded on the evidence, so that is the
        // only one this can vouch for; saying "the code it cites has not changed" would claim more than was done.
        summary: `${item.summary} (carried over from the check on ${(item.capturedAt ?? previous.startedAt).slice(0, 10)}: ${cited.length === 1 ? `${file} has` : `all ${cited.length} files it read (${cited.join(', ')}) have`} not changed since)`,
        runId: item.runId ?? previous.id,
      });
    }
  }

  const note =
    skip.size === 0
      ? ''
      : `${skip.size} requirement${skip.size === 1 ? '' : 's'} kept the verdict from the earlier check, because every file ${skip.size === 1 ? 'it read has' : 'they read has'} not changed since.`;
  return { skip, evidence, note };
}
