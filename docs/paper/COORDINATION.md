# What coordinating several AI sessions cost, and what it bought

For most of the project, several Claude Code sessions worked on the same repository at once, each in its own
worktree, merging into the same `main`. This counts what keeping them out of each other's way cost, and what having
more than one of them bought. Every event is one row of `coordination.csv`, with its date, the sessions involved,
and its source: a commit, a pull request, or a line of the backlog. The figure is `figure-coordination.html`.

The record runs from the start of the surviving history, 09:32 on 18 September, to 16:18 on 28 September (`main` at
`57fed49`, 469 changes). Times are Eastern.

## The cost

**93 of the 469 changes to `main` (20%) did nothing but coordinate.** Each touched only the backlog: 81 claimed
work, 4 took or released the evaluation harness, and 8 released a claim, withdrew one, or noted a duplicate. Eight
more claims were made inside a change that also did work.

| Day | Changes to `main` | Coordination only | Conflicts resolved by hand |
|---|---|---|---|
| 18 September | 15 | 0 | 1 |
| 19 September | 45 | 0 | 0 |
| 20 September | 48 | 2 | 0 |
| 21 September | 0 | — | — |
| 22 September | 10 | 4 | 0 |
| 23 September | 12 | 4 | 0 |
| 24 September | 37 | 0 | 1 |
| 25 September | 57 | 2 | 7 |
| 26 September | 118 | 34 | 29 |
| 27 September | 89 | 31 | 12 |
| 28 September, to 16:18 | 38 | 16 | 6 |

The rule that work is claimed in the backlog was adopted on 20 September, after two sessions each built the same
recipe (below). It cost little while two or three sessions were working. From 26 September, when seven or more were,
about a third of all changes to `main` were claims.

**A claim was quick.** Where a claim can be paired with the work it claimed (54 pairs), the work reached `main` a
median of 18 minutes later; half of them took between 11 and 36 minutes, and the longest took just under two hours.

**Conflicts were mostly about the backlog itself.** Working branches brought `main` in 127 times, and 56 of those
merges needed lines written by hand that matched neither side. **36 of the 56 were in `docs/BACKLOG.md`, and for 31
it was the only file.** The next most common was `docs/COVERAGE.md` (15), a generated file that every change to a
rule rewrites. Conflicts in code were rare: 4 in one crate's `lib.rs`, 4 in `signed_in.rs`, and a few single files.
The file every session had to write to, so that no two would build the same thing, was the file they collided in.

**Pull requests.** Of #1 to #375, 350 merged and 25 did not. Of the 25:

- 14, from 19 to 23 September, reached `main` another way, before work went through pull requests as a rule;
- 4 were automated dependency updates;
- 3 were still open when this was measured;
- 2 conflicted with a backlog paragraph and were carried word for word by another pull request (#163, #166);
- **3 were work thrown away because another session had done the same thing** (#63, #331, #342).

**Duplicated work and collisions, 14 recorded:**

- **18 September:** two branches merged the same evening left `main` unable to compile (`e78472b`, repaired in #3).
- **19 September:** ten agreed work items had lived only in a chat between two sessions (`da2d956`).
- **20 September:** two sessions each read the backlog, each correctly saw the query recipe unclaimed, and both
  built it, which cost "two hours" (`7c692b5`). This is what the claim rule was written for.
- **20 September:** both sessions ran the evaluation harness at once for eight minutes, each having said in a
  message that it would say something first (v1's `CLAUDE.md`).
- **22 to 26 September:** sessions working on `sv` "collided five times in one day". This is recorded once, with no
  dates or instances, so none can be counted here.
- **25 September:**
  - the same wording fix was built twice in one night (#63 and a cloud session's version);
  - a backlog entry was deleted by accident and restored;
  - two sessions answered the same question from the owner separately (`f5d2d77`).
- **26 September:** a duplicate claim on the container was withdrawn eleven minutes later (#206, #207), and a
  backlog entry was noted as possibly repeating a finished one (#158).
- **27 September:**
  - one item was built twice (#244);
  - claims were signed with the wrong session's name (`3d059e4`);
  - one review item was claimed twice, a minute apart (#328, #329).
- **28 September:** a second review item was claimed twice, 27 seconds apart, and built in opposite directions (#340,
  #341); the owner closed one version.

Duplicates still happened after the claim rule, in two ways. Twice the same need was met from two directions, by
sessions working on different items (#63 on 25 September, #244 on 27 September). Twice two sessions claimed the
same item minutes apart, before either claim had reached `main`: a claim is only seen once it merges, and merging
took a few minutes of checks.

## What it bought

**Sessions found faults in each other's merged work that no test had caught.** In the fault ledger
(`TESTS-AND-FAULTS.md`), review by another session found **28 of the 148 faults**: 10 in v1, 18 in `sv`. That is more
than any other single way except the owner's own use, and three times as many as a failing test (9).

- **v1, 19 September:** one session read the other's half of the code looking for one pattern, SecureVibe "doing
  the right thing and saying the wrong thing", and found nine (`a4e4fbf`). The most serious was about money: a tool
  reported "skipped" after it had already sent files to the AI service and charged the owner's key.
- **`sv`, 25 and 26 September:** ten single findings, each in a commit that says another session found it. Among
  them, a line marked `# nosec` made a scanner report nothing and `sv` counted a clean run (#73), an unanswered
  question excluded twelve requirements (#128), and a rate-limit check credited V6.3.1 having tested nothing
  (`672d4af`).
- **`sv`, 27 September:** a review at the owner's asking found thirteen items, five of them faults (#315).
- **28 September:** the owner asked two sessions to review each other's work; neither review found a fault.

Parallel sessions also meant more work done: 118 changes reached `main` on 26 September, the day with the most
sessions (at least seven named ones).

## Sessions per day

Named from commit messages, claims, and backlog lines. Local sessions often did not sign their work, and names are
not reliable identities (one cloud session signed as two different names on different days), so these are lower
bounds.

| Day | Sessions that signed something |
|---|---|
| 18 September | 1 |
| 19 to 20 September | 2 |
| 22 to 23 September | none signed |
| 24 September | 2 |
| 25 September | 4 |
| 26 September | at least 7 |
| 27 September | 7 |
| 28 September | 6 |

## What this shows

- **Coordination had a measurable price, and most of it was paid in one file.** A fifth of all changes existed only
  to claim or release work, and two-thirds of the conflicts people resolved by hand were in the backlog those claims
  were written to. The cost rose with the number of sessions: about one change in nineteen before 26 September, one
  in three after.
- **The claim rule reduced duplicated work but did not end it.** It cannot stop two claims made minutes apart, before
  either can be seen, or two sessions meeting the same need from different items. Those two account for all the
  work built twice after 20 September.
- **Review between sessions was one of the project's best fault-finders.** It found about one fault in five, three
  times what failing tests found. A second session read the first one's work as an outsider would, and that is what
  caught the faults that tests written by the first session could not.
- **Work thrown away was small.** Three pull requests out of 375 were discarded because another session had done the
  same thing, and one more version was withdrawn before it was published (#244).

## Limits

- **Time is mostly unmeasured.** Commit times say when a change finished, not when it started. The only stated costs
  are the two hours of the duplicated recipe and the eight minutes of the harness collision.
- **56 conflicts is a lower bound.** A conflict resolved by taking one side whole leaves no trace, and merges in
  worktrees that were deleted before pushing are not in the repository. A few of the `COVERAGE.md` conflicts may
  have been the file being regenerated rather than a real clash.
- **Messages between sessions are not in the repository.** They carried the early agreements and claims, and some of
  the collisions.
- **Which unmerged pull requests were closed and which were open** was read from git, not from GitHub, whose tools
  were not usable where this was measured; #369, #374, and #375 were open at the time.
- **Classifying a change as a claim is by its title or branch name.** Six uses of "claim" meaning "assertion" were
  excluded by hand.
