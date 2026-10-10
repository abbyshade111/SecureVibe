# Process: shorter CI, a merge queue decision, and a nightly routine on `main`

**Status:** partly done: parts 1 (shorter CI) and 2 (a merge queue, a repository setting and the owner's to decide)

From the same write-up; each
claimable on its own, and the second is the owner's to decide.
1. **Shorter CI.** The test job is one job of about ten minutes and `sv-check` is most of it: a matrix that runs
   `sv-check` in two or three shards beside the other crates brings it to about five; docs-only pull requests skip
   the test and image jobs behind a path filter, with a job of the required name still reporting. ADR-051 governs
   `rust.yml`: a Later entry or an "unchanged, because" line.
   **Part status:** open
2. **A merge queue** (a repository setting, the owner's). GitHub merges a pull request that was green against an
   older `main`, so the first test of the combination is `main`'s own; a queue tests each pull request on top of
   the ones ahead of it, at one more CI run each. The write-up's advice: try auto-merge alone first (on since
   8 October), and turn the queue on only if `main` goes red from an untested combination more than once a week.
   **Part status:** open
3. **A nightly routine on `main`.** The full workspace tests with a container backend, `tools/coverage.py
   --credits`, and the example apps re-scored, with the counts compared to the night before and a one-line note
   when anything changed. The pieces exist; the comparison does not. The weekly decision-record review's routine
   ("A weekly review of the decision records") is the model.
   **Part 3 claimed 8 October 2026 by session securevibe-review**, at the owner's word ("can you help me set up the
   nightly routine you proposed"), in branch `claude/securevibe-review-nightly`, in the form of a `schedule` trigger
   on `rust.yml` (ADR-051, Later) rather than a Claude routine, since CI already runs every piece with Docker; parts
   1 and 2 stay open.
   **Part 3 done the same day** (ADR-051, Later, 8 October 2026; design entry "A nightly run on main, and the example
   apps' verdicts held to a snapshot"): a `schedule` trigger on `rust.yml`, 03:17 UTC daily, running the `test` and
   `image` jobs on `main`; the `publish` job keeps its push-only condition. The comparison the write-up wanted is the
   snapshot test of the ideas item's part 2.
   **Part status:** open

**The owner's decision, 9 October 2026**, asked by session securevibe-e2 with a recommendation for each open choice: **part 2, the merge queue: hold off for now, as recommended.** Auto-merge alone stays; the queue is reconsidered only if `main` goes red from an untested combination of pull requests more than once a week. (On 9 October one such combination, #1246 with #1248, turned `main` red once; #1255 fixed it.)
