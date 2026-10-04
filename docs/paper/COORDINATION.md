# What coordinating several AI sessions cost, and what it bought

For most of the project, several Claude Code sessions worked on the same repository at once, each in its own
worktree, merging into the same `main`. This counts what keeping them out of each other's way cost, and what having
more than one of them bought. Every event is one row of `coordination.csv`, with its date, the sessions involved,
and its source: a commit, a pull request, or a line of the backlog. The figure is `figure-coordination.html`.

The record runs from the start of the surviving history, 09:32 on 18 September, to **11:37 on 4 October** (`main` at
`157ddc3`, Merge PR #564; 655 changes). Times are Eastern. The first version of this analysis ran to 16:18 on 28
September (`main` at `57fed49`, 469 changes); where a number has changed, both are given. Nothing reached `main`
between 22:44 on 29 September and 10:32 on 3 October. A change is one step in `main`'s own history (its first-parent
commits): a pull request's merge, a rebased pull request, or a commit made directly on `main`. `TIMELINE.md` lists 569 of
the 655, those from the evening of 20 September on.

## The cost

**172 of the 655 changes to `main` (26%) did nothing but coordinate** (93 of 469, 20%, to 28 September). Each
touched only the backlog: 166 claimed work, 4 took or released the evaluation harness, and 10 released a claim,
withdrew one, or noted a duplicate. Fourteen more claims were made inside a change that also did work (8 to 28
September).

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
| 28 September, from 16:19 | 45 | 17 | 2 |
| 29 September | 48 | 21 | 13 |
| 30 September to 2 October | 0 | — | — |
| 3 October | 76 | 34 | 27 |
| 4 October, to 11:37 | 17 | 7 | 5 |

The rule that work is claimed in the backlog was adopted on 20 September, after two sessions each built the same
recipe (below). It cost little while two or three sessions were working. From 26 September, when seven or more were,
about a third of all changes to `main` were claims. **In the last week it was 42%: 79 of the 186 changes after 16:18
on 28 September** (77 claims and 2 releases). Securevibe-e2 signed 41 of them and securevibe-e9 23; most of the rest
were securevibe-e10's, on branches it did not sign.

**A claim was still quick.** Where a claim can be paired with the work it claimed, the work reached `main` a median
of 18 minutes later to 28 September (54 pairs). After that, pairing each claim branch with the work branch of the
same name (51 pairs), the median was 23 minutes; half took between 15 and 42 minutes, and the longest just under
three hours (#395 to #396, merging the CI-hang fix into v1).

**A plan for several sessions, carried out by one.** On 28 September securevibe-e9 wrote a plan for splitting
`signed_in.rs`, the 15,463-line file the signed-in checks lived in, so that several sessions could each move one slice: the
file was frozen from the first claim to the last step, with rules for every step so that two sessions' moves would
not conflict (#335). In the event one session, securevibe-e2, did all ten steps between 15:22 and 19:05, each with a
claim of its own: twenty pull requests (#353 to #405), ten of them claims that no other session was competing for.
The freeze and the claims protected against a collision that did not happen; they were cheap, at a few minutes each.

**Conflicts moved from the backlog to the design document.** Working branches brought `main` in 94 times after 28
September, and 47 of those merges needed lines written by hand that matched neither side (56 of 127 to 28
September; **103 in all**). In the new week **`docs/DESIGN.md` was in 31 of the 47**, and the only file in 12; the
backlog was in 19, and the only file in 10. Every change now added a dated section at the end of the design
document, so any two changes merged near each other met there. `docs/COVERAGE.md`, the generated file, was in 14.
Seven conflicts touched code, among them `mcp.rs` twice, while two sessions worked down the same list of MCP server
items. Over the whole record, the backlog was in 55 of the 103 conflicts (the only file in 41), the design document
in 38, and the coverage file in 29. The files every session had to write to remained the files they collided in.

**Pull requests.** GitHub's record (`prs.json`, fetched 4 October at 11:39) counts **551 of the 564 pull requests
opened by the cut-off as merged, 11 as closed unmerged, and 2 as open.** This corrects the first version, which read
git rather than GitHub and found 25 of #1 to #375 unmerged:

- the 14 from 19 to 23 September that "reached `main` another way", and #15, are recorded by GitHub as merged; their
  commits arrived under different hashes, so git could not see it;
- #369, #374, and #375, open on 28 September, merged later;
- #119, which the first version missed, was closed and opened again from the same branch two seconds later as #120,
  which merged.

Of the 551, 548 merged into `main`, 2 into the `v1` branch (#272 and #396), and 1 into another working branch (#6).
`TIMELINE.md` counts 528 pull requests from git instead, the ones that reached `main` as a change of their own from the
evening of 20 September. The other 20 merged into `main` are #1 to #4, before that evening; #308 and #383, whose commits
arrived inside other pull requests; and #5, #7 to #18, and #20 (the first version's 14 less #6, plus #15), whose commits
arrived under other hashes.

The 11 closed unmerged are:

- 5 automated dependency updates (#230, #231, #232 on 27 September; #468 and #469 on 3 October);
- 2 that conflicted with a backlog paragraph and were carried word for word by another pull request (#163, #166);
- #119, reopened as #120;
- **3 that were work thrown away because another session had done the same thing** (#63, #331, #342). None was added
  after 28 September.

The 2 open at the cut-off, #558 and #562, are fixes for the deep review (below), still in review.

**Duplicated work and collisions, 16 recorded (14 to 28 September):**

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
- **28 September:**
  - a second review item was claimed twice, 27 seconds apart, and built in opposite directions (#340, #341); the
    owner closed one version;
  - **the rate limiter item was claimed twice.** Securevibe-e10 claimed it on its own branch only, never on `main`;
    securevibe-e2 found it unclaimed on `main` and claimed it (#411), as the rule says it should. E10 had finished
    the work by then and told the owner so: "That's my mistake: the project's rule is that a claim counts once it's
    on `main`." The owner chose to merge e10's work (#412) and e2 took the part it left (#415, #416). No code was
    thrown away. The backlog drew the lesson: "a claim counts when it is on `main`, so open its pull request at once."
- **29 September:** two changes gave a backlog item the same number; one was renumbered in a merge (`a0d4192`, "item
  11 was taken, this is item 12").

One collision was avoided rather than had, and is in a transcript only: on 3 October securevibe-e10 left two MCP
server items unclaimed "to avoid a collision" with securevibe-e2, which was working down the same list.

Duplicates still happened after the claim rule, in two ways. Twice the same need was met from two directions, by
sessions working on different items (#63 on 25 September, #244 on 27 September). Three times two sessions claimed
the same item before either claim could be seen on `main`: twice minutes apart (27 and 28 September), and once
because a claim was made on a branch and never merged (28 September).

## A new kind of coordination: work sent between sessions

From 28 September, sessions that did not share a repository sent each other work. The owner's cato-pipeline
project (a separate repository, which wired `sv` into its own pipeline and then ran the owner's comparison study)
had a session that found faults in `sv` while using it. It could not reach the `sv` sessions, and they could not
reach it: "The cato-pipeline session can't receive replies." So the owner carried the work by hand, as a written
report or a link to one. On 28 September the owner asked the cato session to "write that and #2 up and I'll share
that with the agents working SecureVibe to fix", and then asked securevibe-e10 to "open this link to an artifact
from an agent on a different project". An `sv` session checked each claim against `main`, added it to the backlog in
a commit of its own, and usually claimed it in the next. Seven deliveries are recorded (`coordination.csv`, kind
`sent-work`):

| When | What was sent | What came of it by the cut-off |
|---|---|---|
| 28 Sep 16:56 | The cato session worked in `sv` itself, at the owner's asking: `report.json` says what was examined (#383, #388), and later its own report of a false alarm (#413, #414) | Both merged the same night |
| 28 Sep 18:11 | Two limits hit while wiring `sv` into cato (#400) | Both fixed that night (#407, #408) |
| 29 Sep 11:27 | OSV's `last_affected` ignored (#422) | Fixed the same morning (#423) |
| 29 Sep 16:49 | A shell variable read as a credential, and the MCP check's word test (#431) | Fixed (#433), and narrowed |
| 29 Sep 18:25 | Four issues from the comparison study (#441) | Fixed the same evening (#443) |
| 3 Oct 20:19 | Three faults from scanning the owner's family-hub (#533) | All three fixed by 21:05 (#535, #537, #538) |
| 4 Oct 09:54 | The deep review of `sv` at `eff3f17`: 58 findings, in three parts (#553, #556) | S1, the critical one, fixed (#555); S2 to S5 in open pull requests (#558, #562); S12 claimed; 52 neither fixed nor claimed |

Twelve faults found by using `sv` came in this way before the deep review, and all twelve were fixed within a day of
arriving. The channel had costs of its own: the owner was the only courier, a session could not ask the sender a
question, and the reproductions were the sender's ("the reproductions below are cato's and were not rerun").

## What it bought

**Sessions found faults in each other's merged work that no test had caught.** In the fault ledger as it stands at
the cut-off (`faults.csv`, `TESTS-AND-FAULTS.md`: 255 faults, 81 in v1 and 174 in `sv`; 196 fixed and 59 open),
**review by another session inside the project found 40** (10 in v1, 30 in `sv`; 28 of 149 to 28 September), and
all 40 were fixed by the cut-off. **The outside deep review of 4 October found 56 more**, of which 55 were still open.
A failing test found 14, and only 7 of the 230 faults in the product rather than in the tests. In full:

| How the fault was found | Faults | Open at the cut-off |
|---|---|---|
| The outside deep review (cato-pipeline session, 4 October) | 56 | 55 |
| Another session's review, inside the project | 40 (v1 10, `sv` 30) | 0 |
| Building something else | 32 | 0 |
| The owner, or real use | 26 | 0 |
| Running it on real input | 25 | 4 |
| A tool in CI | 16 | 0 |
| v1's evaluation harness | 14 | 0 |
| A failing test | 14 | 0 |
| Another project using `sv` (sent by the cato-pipeline session) | 12 | 0 |
| Breaking a guard on purpose | 11 | 0 |
| Not recorded | 9 | 0 |

The cato-pipeline session's 12 are SV-74, 77, 83, 85, 88, 92, 93, 94, 95, 110, 111, and 113 in the ledger; with the
deep review, a session from another project found 68 of the 255.

- **v1, 19 September:** one session read the other's half of the code looking for one pattern, SecureVibe "doing
  the right thing and saying the wrong thing", and found nine (`a4e4fbf`). The most serious was about money: a tool
  reported "skipped" after it had already sent files to the AI service and charged the owner's key.
- **`sv`, 25 and 26 September:** ten single findings, each in a commit that says another session found it. Among
  them, a line marked `# nosec` made a scanner report nothing and `sv` counted a clean run (#73), an unanswered
  question excluded twelve requirements (#128), and a rate-limit check credited V6.3.1 having tested nothing
  (`672d4af`).
- **`sv`, 27 September:** a review at the owner's asking found thirteen items, five of them faults (#315).
- **28 September:** the owner asked two sessions to review each other's work; neither review found a fault.
- **29 September:** securevibe-e2's first weekly review of the decision records found that ADR-019's "the only
  writable place is a small in-memory folder" was untrue: the app's own container was not run read-only (#464; SV-108).
  The owner agreed it should be, and another session made it so on 3 October (#496).
- **3 October:** securevibe-e2, asked by the owner to look at the MCP server that other sessions had built, found
  eight faults, among them a report written through a link, a malformed request that hung the client or ended the
  server, and a check with no time limit (SV-98 to SV-105). All eight were fixed the same day.
- **3 October:** securevibe-e9's review of the running-app checks, which several sessions had built, found that
  `docs/COVERAGE.md` counted 18 requirements as checkable by a clean run when nothing could credit them (#471, fixed
  in #486; SV-106), and that headers and cookies were credited from too little (SV-107), and proposed more checks.
- **4 October:** the deep review, sent by the cato session, at the owner's asking: six reviewers, 58 findings (13
  about the safety of `sv` itself, 25 about honesty and coverage, 6 about accuracy, 14 about reports and reviews),
  one of them critical; the ledger counts 56 of them as faults. It is the largest single review of the project, by a
  session outside it.

Twelve of the 40 in-project review finds came after 16:18 on 28 September. One more find this week looks like review
but is not counted as one: securevibe-e2, testing its own prompts on 4 October, found that securevibe-e9's new
double-booking check counted one booking as twenty. The ledger counts that as found by running on real input
(SV-117), since it came from a test build rather than from reading the check; it was open at the cut-off.

Parallel sessions also meant more work done: 118 changes reached `main` on 26 September, the day with the most
sessions (at least seven named ones), and 76 on 3 October, with five.

## Sessions per day

Named from commit messages, claims, pull requests, and backlog lines. Local sessions often did not sign their work,
and names are not reliable identities (one cloud session signed as two different names on different days), so these
are lower bounds.

| Day | Sessions that signed something |
|---|---|
| 18 September | 1 |
| 19 to 20 September | 2 |
| 22 to 23 September | none signed |
| 24 September | 2 |
| 25 September | 4 |
| 26 September | at least 7 |
| 27 September | 7 |
| 28 September, to 16:18 | 6 |
| 29 September | 4: securevibe-e2, e9, e10, and the cato-pipeline session |
| 30 September | 2 in the backlog (securevibe-e2, e9); no change reached `main` |
| 1 to 2 October | none |
| 3 October | 5: securevibe-e2, e9, e10, practical-banach-b1faa1, and the cato-pipeline session |
| 4 October, to 11:37 | 4: securevibe-e2, e9, e10, and the cato-pipeline session |

## What this shows

- **Coordination had a measurable price, and it kept rising.** A quarter of all changes existed only to claim or
  release work: about one change in nineteen before 26 September, one in three from 26 to 28 September, and two in
  five in the last week. Part of the last week's share was ceremony: ten claims for a split no other session was
  competing for.
- **The friction moved to whichever file every change wrote to.** First the backlog, then the design document once
  each change added a section to its end. Code itself rarely conflicted.
- **The claim rule reduced duplicated work but did not end it.** It cannot stop two claims made before either can be
  seen, and a claim made on a branch is not seen at all. No work was thrown away in the last week; the one double
  claim was settled by the owner before code was duplicated.
- **Review between sessions was one of the project's best fault-finders, and it reached beyond the project.** It
  found 40 faults inside the project, nearly three times what failing tests found (14), and an outside session's
  review found 56 more. A second session read the first one's work as an outsider would. In the last week the outsider
  was sometimes a session from another project, using `sv` for real and sending what it found; all 12 faults it sent
  before the deep review were fixed within a day.
- **Work thrown away stayed small.** Three pull requests out of 564 were discarded because another session had done
  the same thing, and one more version was withdrawn before it was published (#244).

## Limits

- **Time is mostly unmeasured.** Commit times say when a change finished, not when it started. The only stated costs
  are the two hours of the duplicated recipe and the eight minutes of the harness collision.
- **103 conflicts is a lower bound.** A conflict resolved by taking one side whole leaves no trace, and merges in
  worktrees that were deleted before pushing are not in the repository. For the new week the merges were read from
  `main` and the branches on the remote at the cut-off; branches already deleted are missed. A few `COVERAGE.md`
  conflicts may have been the file being regenerated rather than a real clash.
- **Messages between sessions are not in the repository.** They carried the early agreements and claims, some of
  the collisions, and, from 28 September, the work sent from cato-pipeline, which the owner carried by hand.
- **Transcripts.** Securevibe-e10's transcript is on this machine (the `loadonce` worktree), and so are the
  cato-pipeline and practical-banach sessions'. Securevibe-e2's and securevibe-e9's are not, so for them the record
  is git, the pull requests, and the backlog only.
- **Classifying a change as a claim is by its title, its pull request's title, or its branch name.** Six uses of
  "claim" meaning "assertion" were excluded by hand to 28 September. After that, 13 changes that touched only the
  backlog were left out because they added entries or records rather than claiming (for example #400, #471, #556),
  and a change that both added an entry and claimed it was counted as a claim, as before.
- **The 51 claim-to-work pairs after 28 September** match a branch ending `-claim` to a branch of the same name
  without it; a claim whose work went in under another name is not paired.
