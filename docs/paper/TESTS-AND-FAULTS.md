# More tests, fewer surprises?

Both versions of SecureVibe grew large test suites quickly: v1 from 810 to 1,078 tests in four days, `sv` from 54 to
1,655 in under two weeks. This sets that growth beside every fault found in SecureVibe's own code, and asks whether
more tests meant fewer faults got through, how the faults that got through were found, and whether the suite learned
from each one. Every fault is one row of `faults.csv`, with when and how it was found, whether it was fixed by the
cut-off, whether the fix added a test, and its source. The day-by-day figures are in `tests_by_day.csv`, and the
figure is `figure-tests-faults.html`.

**The record runs to the cut-off: `main` at `157ddc3`, 11:37 Eastern on 4 October 2026.** The first version of this
document ran to 16:18 on 28 September, with 149 faults. From 28 September the sessions that did most of the work left
no transcript on this machine, so from then on the record is git, the pull requests, and `docs/BACKLOG.md`. Those are
what every row below rests on.

**The short answer is still no.** The rate of faults did not fall while `sv`'s suite grew thirtyfold; after
28 September it rose. What predicted faults was how much new code was written, and how many people and processes
were looking at it. Almost every fault the tests missed did get a test when it was fixed.

## The faults

**255 faults in eighteen days: 81 in v1 and 174 in `sv`** (149 to 28 September, 106 since). A fault here is anything
in SecureVibe's own code or checks that was found and has a named source: a bug, a crash, a security weakness, a wrong
result, or a verdict that failed open. Feature work, speed-ups, pure formatting fixes, and wrong claims in documents
are left out (those are in `CORRECTIONS.md`). A false alarm raised by one of `sv`'s rules counts as a wrong result,
as it always has.

**One thing changed in what counts.** Until 28 September every fault in the ledger had been fixed. On 4 October an
outside review reported 58 findings at once, and nearly all were still open at the cut-off. Each one that is a real
fault is counted as found, with whether it was fixed. So the 255 are **196 fixed and 59 open**:

- 56 of the review's 58 findings are counted; 1 was fixed by the cut-off (S1, the most serious), and 55 were open.
  The two left out are the two the review itself marked *plausible*, not demonstrated (S11 and H16). They are in
  `faults.csv` with `in_counts` set to no.
- 4 false alarms found in the prompt-library test builds on 3 and 4 October were also open.
- Everything else found since 28 September, 46 faults, was fixed by the cut-off.

By 16:30 the same day, 13 more of the review's counted findings were fixed (S2 to S6, S12, R1, R2, H8, H10 to H13), and
H4 in part, so 14 of the 56 rather than 1. Six of those (R1, H8, H10 to H13) are among the 24 that fail open, described
below. The table and `faults.csv` keep the cut-off; `SINCE-THE-CUTOFF.md` has the afternoon.

230 of the 255 were in the product; the other 25 were tests that were weak or broken, which matters because a test
that cannot fail guards nothing.

| How it was found | v1 | `sv` | Total | Open at the cut-off |
|---|---|---|---|---|
| **An outside review of the code (4 October)** | — | 56 | 56 | 55 |
| Another session reviewing the work | 10 | 30 | 40 | — |
| Building or designing something else | 9 | 23 | 32 | — |
| The owner, or real use | 20 | 6 | 26 | — |
| Running it on real input | 11 | 14 | 25 | 4 |
| An automated tool in CI (CodeQL, clippy, lints) | 11 | 5 | 16 | — |
| v1's evaluation harness | 14 | — | 14 | — |
| **A failing test** | **1** | **13** | **14** | — |
| **Another project using `sv` (cato-pipeline)** | — | 12 | 12 | — |
| Breaking a guard on purpose, to see which tests fail | 2 | 9 | 11 | — |
| Not recorded | 3 | 6 | 9 | — |
| **Total** | **81** | **174** | **255** | **59** |

On 28 September the order of the first rows was review 28, the owner 26, real input 21, and building something else
19.

**Two new rows, and why they are not "another session reviewing".** The outside review was a deliberate audit of
`sv`'s code at `eff3f17`, done in one morning by six reviewers working for another of the owner's projects
(cato-pipeline), each finding reproduced with a harmless fixture or confirmed from the code. Folding its 56 into the
review row would hide the largest single source in the ledger behind a category that until then meant one session
reading another's merged pull request. The other new row is that same project using `sv` for real: wiring it into its
own pipeline on 28 September, and the owner's comparison study of five apps from 29 September to 3 October. It found
12 faults: one for each of the study's ten reported issues (issue 7 had a second half, the 2 MB read limit, which was
reported honestly as "not run" and is a limit, not a fault: SV-118, not counted) and 2 from the integration.

**Of the 230 faults in the product, 7 were caught by a failing test** (5 of 129 on 28 September). The two new ones
were found together, when `killed_run.rs` failed on the owner's Mac: a run that cleaned up after an earlier one and
then failed said nothing of what it removed, and an app folder Colima could not see was reported only as an app that
never answered. Breaking a guard on purpose, the practice `CLAUDE.md` asks for, found 11 faults, and all 11 were in
the tests. That is what it is for. It checks the tests, not the product.

**52 verdicts failed open**, telling someone something was verified when it was not (22 on 28 September). 24 are the
outside review's and were open at the cut-off. The 28 that were fixed were found by building something else (8),
review (7), the owner's use (6), a failing test (2), real input (2), not recorded (2), and the other project (1).
These are the faults whose `kind` in `faults.csv` is `fail-open`. `TOP10.md` counts 43 on another basis: the incidents
it names under A10, 13 fixed before the review and 30 of the review's findings, among them some this ledger classes as a
security fault (S6), a bug (H22, H24, H25, R6), or a wrong result (R2, R3), and H16, which it leaves out as plausible.

## Tests and faults, day by day

| Day | Version | Tests at the end of the day | Lines of code changed | Faults found | By a failing test | Faults per 1,000 lines |
|---|---|---|---|---|---|---|
| 17 September | v1 | 810 | — | 5 | 0 | — |
| 18 September | v1 | 949 | 11,594 | 7 | 0 | 0.6 |
| 19 September | v1 | 1,002 | 6,036 | 36 | 0 | 6.0 |
| 20 September | v1 | 1,078 | 4,714 | 19 | 0 | 4.0 |
| 22 September | `sv` | 54 | 5,045 | 1 | 0 | 0.2 |
| 23 September | `sv` | 54 | 4,349 | 0 | 0 | 0 |
| 24 September | `sv` | 320 | 11,021 | 12 | 2 | 1.1 |
| 25 September | `sv` | 687 | 29,677 | 15 | 0 | 0.5 |
| 26 September | `sv` | 1,126 | 36,231 | 17 | 1 | 0.5 |
| 27 September | `sv` | 1,306 | 13,829 | 17 | 2 | 1.2 |
| 28 September | `sv` | 1,417 | 11,379 | 24 | 7 | 2.1 |
| 29 September | `sv` | 1,491 | 6,217 | 12 | 1 | 1.9 |
| 3 October | `sv` | 1,645 | 15,115 | 19 | 0 | 1.3 |
| 4 October, to 11:37 | `sv` | 1,655 | 787 | 57 | 0 | — |

Nothing was committed from 30 September to 2 October. On 4 October, 56 of the 57 faults are the outside review's,
which read all of `sv`'s code rather than that morning's, so a rate per line changed that day means nothing.

The 28 September row is now the whole day. It replaces the row to 16:18 (1,341 tests, 6 faults, 12,200 lines, 0.5 per
1,000). Its lines changed also leave out the commits that split `signed_in.rs` into one file per area, 37,843 lines
moved and not changed; the earlier row counted the first of those in part.

v1 also had 14 faults found from 23 to 26 September, in light maintenance after `sv` began; they are in the files.
v1's test counts are the figures stated in its commits (17 September's from the first session's own record). `sv`'s
are the `#[test]` lines on `main` at the last change of each day. Lines changed leave out documents, data, lockfiles,
and large moves of files. From 28 September they are counted from `crates/`, `tools/`, `examples/`, the `Dockerfile`,
and `Cargo.toml`, with renamed files followed, which gives 27 September's 13,829 exactly; the rows before 28 September
are as first published.

## Does a pattern hold?

These are descriptions of fifteen days of work, not a test of anything, and several sessions were working at once.
(Eighteen calendar days, 17 September to 4 October, with no work on 21 September or from 30 September to 2 October;
this said "thirteen" until 4 October, which counted only 17 to 29 September.)

- **The rate did not fall as the suite grew; it rose.** From 24 to 27 September `sv` found between 0.5 and 1.2 faults
  per 1,000 lines changed while the suite grew from 320 tests to 1,306. From 28 September to 3 October it found 1.3
  to 2.1, while the suite grew to 1,645.
- **Faults still followed code written, less tightly.** Across `sv`'s nine days with code changed, from 22 September
  to 3 October, the days with more lines changed found more faults, with a rank correlation of 0.72. Across the first
  seven days it was 0.90.
- **Faults followed who was looking.** The rise after 28 September came with new lookers. Another project using `sv`
  found 12 faults, a session reviewing the MCP server found 8, a review of the running-app checks found 2, and the
  first weekly review of the decision records found 1. Then one outside review on the morning of 4 October found 56,
  more than everything fixed in the six days before it (46). v1 showed the same thing on 19 and 20 September, when
  the owner's use and review by another session found most of its faults.
- **`sv`'s tests did catch more than v1's.** 22 of its 174 faults were found by a failing test or by breaking a guard,
  against 3 of v1's 81. But 16 of those 22 were faults in the tests themselves, so for faults in the product the
  difference is small: 6 of 155 in `sv`, 1 of 75 in v1.

## Did the suite learn from each surprise?

**Mostly, yes.** Of the 164 faults in the product that the tests missed and that were fixed by the cut-off, 159 can be
checked (the other five were fixed in 17 September's history, which was lost). **The fixing commit added or changed a
test for 141 of the 159 (89%)**: 56 of 69 in v1 (81%), and 85 of 90 in `sv` (94%). 126 of those added a new test.
On 28 September it was 104 of 119 (87%).

Since 28 September, 37 of 40 fixes left a test. The three that did not: a Python script that needs the network
(`tools/pwned_passwords.py`, which read a file the split had moved), a one-line change clippy 1.99 asked for, and a
count in `docs/COVERAGE.md` whose test the fixing session judged it could not write reliably. The 59 faults still
open are not in these numbers.

So each surprise made the suite larger. It did not make the next surprise less likely, because the next one was
somewhere the suite had not been told to look.

## What the outside review adds

The review of 4 October is the clearest case of the pattern above. It read `sv` at `eff3f17`, when the suite had 1,645
tests. It found 1 critical, 26 high, 22 medium, and 9 low findings by its own count. Of the 56 counted
here:

- **24 fail open.** Each says *checked* where `sv` should say *not verified*: a SQL rule that knows only a short list
  of calls (H1), Svelte and Vue templates never read (H2), a redirect to plain HTTP credited as one to HTTPS (H12),
  HSTS credited at `max-age=0` (H13), an AI tool marking its own findings as reviewed by a person (R1).
- **12 are about the safety of `sv` itself:** a backslash in a file name that let `sv bundle` read outside the app
  (S1, critical, fixed 12 minutes after it reached the backlog on `main`, both times taken from the merges; by commit
  time, the five minutes from 09:54 to 09:59 that `faults.csv` records), a fence the app could cross to the host's gateway
  (S2), files written through links (S3, S4), a planted report taken as a real run (S6).
- **The rest** are wrong results, among them the false alarms of A1, the same pattern the prompt-library builds had
  found the day before (SV-114 and SV-116), and bugs such as `sv report` exiting 0 whatever happened (R6).

None of these was a test failing. Several are the kind a test written from the code agrees with: the "v6" lockfile
test used v5's format (H24), and the only fence test tried the internet, not the host (S2).

## What this shows

- **Tests confirm what someone thought of, and the faults were in what nobody had thought of.** A fault that a test
  can catch is one whose shape was known when the test was written. Almost all of the 255 were found by a person or a
  process looking at the whole: using it, reviewing it, running it on something real, or building the next thing.
- **A growing suite is not a sign of falling risk.** `sv`'s suite grew from 320 tests to 1,655, and the rate of faults
  per line of new code went up, not down. Then a review of a few hours found 56 more. The count of tests measures
  effort, not safety.
- **The more independent the looker, the more it found.** A session reviewing another's pull request finds faults in
  that change. A project using `sv` for its own ends found faults no session building `sv` had reason to look for. A
  review commissioned to find faults, by people with no stake in the code, found the most.
- **The suite still earned its keep.** 89% of the faults that got through and were fixed left a test behind, so none
  of them came back. That is protection against regression, which is what a test suite is good at.
- **This is the same finding as the corrections ledger, from the other side.** `CORRECTIONS.md` found that 3 of 76
  wrong claims were caught by a failing test; here, 7 of 230 product faults were.

## Limits

- **"Found" is often the time of the fix.** Where no earlier report exists, the fault's found time is the fixing
  commit's, so the time between finding and fixing is zero for many rows. The review's findings are dated when each
  part reached the backlog (09:54 and 10:06 on 4 October). Three prompt-library false alarms have no recorded time.
- **How each fault was found is a judgment,** made from the commit message, the pull request, and the backlog; nine
  rows record no finder. Two from 28 September are counted as found by a failing test because a failing test led to
  them, though a person read the aftermath.
- **One commit can fix several faults,** and they share its answer about whether a test was added: one v1 commit
  added one test for seven faults, and one `sv` commit (#477) fixed four of the MCP server's.
- **Open faults are counted as reported.** The review's severities and confidence labels are its own; they were not
  re-checked here, except that the two it marked *plausible* are left out. A finding that turns out not to be a fault
  when someone fixes it would leave the count.
- **Overlap is counted in both places.** The review's A1 and two prompt-library false alarms are the same weakness
  (rules that cannot tell a constant from input), found a day apart.
- **Only faults that were written down are here.** Faults never found are not. V1-06, the CI hang, stayed on a
  branch until 28 September, when it was merged into the `v1` branch (#396); the tags `v1-paper` and `v1-final`
  still have the hanging line, and the fix has not been run on a Linux runner.
- **Pre-merge weaknesses in a pull request's own new tests,** found by breaking its new guards before it merged, are
  development, not faults, and are not counted. Faults in code already on `main`, and CodeQL findings in new test
  code (as on 25 September), are.
- **v1's counts from 23 September on** are a static count of test calls in the code, which runs 60 to 160 below the
  numbers stated in its commits; they are in `tests_by_day.csv`, not in the table above.
- **Fifteen days is a small sample,** and the busiest days had the most sessions, the most code, and the most use at
  once, so none of these can be separated from the others.
