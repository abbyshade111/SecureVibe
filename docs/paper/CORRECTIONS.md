# What the checks claimed, and what turned out to be true

SecureVibe's purpose is to tell a person what is and is not verified about their app. This is the record of every
time it told somebody something that was later found to be wrong: a number, a status, or a verdict reported to the
owner, printed in a report, counted in `docs/COVERAGE.md`, or stated in its own documents. Every correction is one
row of `corrections.csv`, with its date, what was claimed before, what it became, why, how it was found, and the
commit or pull request. The figure is `figure-corrections.html`.

**The record runs to the cut-off: `main` at `157ddc3`, 11:37 Eastern on 4 October 2026.** The first version ran to
28 September, with 48 corrections, the last on 27 September. From 28 September the sessions that did most of the work
left no transcript on this machine, so from then on the record is git, the pull requests, and `docs/BACKLOG.md`.

## The count

**76 corrections in seventeen days, 17 in v1 and 59 in `sv`** (48 to 27 September; 28 since, all in `sv`).

| Direction | v1 | `sv` | Total |
|---|---|---|---|
| **Down:** the claim was stronger than the evidence | 8 | 47 | 55 |
| **Up:** the claim was weaker than the evidence | 6 | 8 | 14 |
| **Wording:** the claim was true, but read as something else | 3 | 4 | 7 |

Nearly three in four went down (two in three on 27 September). A checker that errs tends to err toward telling people
their app is safer than it is, because every shortcut in a check (a tool that ran on nothing, a silence read as "no",
a citation one digit off, a rate limiter's refusal read as the app's) makes the report greener, never redder. Upward
corrections were mostly v1 counting against requirements its apps met, and `sv` failing to show checks it had
actually made. A false alarm withdrawn counts as down, as it did on 20 and 26 September (rows 15 and 43): the claim
of a fault was stronger than the evidence.

By day: 3 on 18 September, 5 on the 19th, 8 on the 20th, none on the 21st or 22nd, 1 on the 23rd, 7 on the 24th,
14 on the 25th, 6 on the 26th, 4 on the 27th, **15 on the 28th**, 7 on the 29th, none from 30 September to
2 October (nothing was committed), 6 on 3 October, and none on 4 October to the cut-off. The two peaks are days `sv`
added the most: on the 25th its test count more than doubled, from 320 to 687; on the 28th it gained 111 tests and
was wired into another project for the first time.

**What was found on 4 October and not yet fixed is not here.** A deep review of `sv`'s code that morning reported 58
findings, and 24 of them are checks that say *checked* where they should not (`TESTS-AND-FAULTS.md`). None had been
corrected by the cut-off, so none is a correction yet. When they are fixed, most will be rows here, and nearly all
of those will go down.

## How each was found

| How it was found | Corrections | To 27 September |
|---|---|---|
| Building or designing something else, which exposed it | 19 | 9 |
| Somebody read the output, the data, or a number, and it did not add up | 15 | 15 |
| One AI session reviewing another's work | 13 | 8 |
| **Another project using `sv`** (cato-pipeline, and one other project's agent) | **10** | — |
| The owner, or somebody using SecureVibe for real | 9 | 9 |
| Running a tool, or SecureVibe itself, on real input | 6 | 4 |
| **A failing test** | **3** | **2** |
| Not recorded | 1 | 1 |

These groups are a judgment from each commit's own account, and `corrections.csv` gives that account for every row.
The new group is the owner's other project, cato-pipeline, which wired `sv` into its own pipeline on 28 September and
ran the owner's comparison study of five apps from 29 September to 3 October; one of its rows (58) came from another
project's agent whose report led a session to the fault.

**Three of 76 were caught by a test failing**:

- a TypeScript file that does not parse was being counted as clean (row 22);
- a sign-in that quietly failed could credit the signed-in guard (row 47);
- an app folder the container backend could not see was reported as an app that never answered (row 54), found when
  `killed_run.rs` failed on the owner's Mac.

Over the same days, `sv`'s tests grew from 54 to 1,655, and v1's server tests from 810 to 1,078:

| Day | `sv` tests (`#[test]`, last commit on `main` that day) | v1 server tests (as stated in commits) |
|---|---|---|
| 17 September | — | 810 |
| 19 September | — | 1,002 |
| 20 September | — | 1,078 |
| 22 September | 54 | — |
| 23 September | 54 | — |
| 24 September | 320 | — |
| 25 September | 687 | — |
| 26 September | 1,126 | — |
| 27 September | 1,306 | — |
| 28 September | 1,417 | — |
| 29 September | 1,491 | — |
| 3 October | 1,645 | — |
| 4 October, to 11:37 | 1,655 | — |

This does not make the tests useless: they guard what the code does. What they cannot catch is a claim that is
wrong while the code does exactly what it was written to do. A test written from the same
understanding as the code agrees with the code. `docs/DESIGN.md` names the extreme case, citation tests written from
the citation map: "a test that checks the code against itself".

## The corrections worth reading first

- **Semgrep "ran, 0 findings" in twenty runs over five apps (row 11).** It had read no files at all, because it reads
  only files tracked by git and no app folder was a repository. Found when the owner asked why a Python app scored
  zero.
- **"0 of 106 verified" on a Flask app (row 10).** Seven of its eight code files had never been read. The corrected
  report says "not assessed" and how much was read. Then rerunning the reports brought the old score back (row 12),
  because the rewrite path worked it out again.
- **The self-check's 4 critical and 113 high (row 16).** 103 came from four rules that assume an app built from v1's
  own template. Six matches were real, and none was a vulnerability.
- **Every citation in two rule maps (row 21).** They were plausible, each one or two digits from the right
  requirement, and their tests had been written from the maps themselves.
- **`# nosec` credited as a clean run (row 30).** A line told bandit to look away, and `sv` took the silence as a
  pass.
- **Silence on two questions excluded twelve requirements (row 39).** An unanswered question was read as "no".
- **Coverage 129 → 125 (row 41).** Semgrep was counted through rules that no pack it runs actually loads. The public
  count went down when it was made honest.
- **Nine "owner's" notes that the AI tool wrote (row 44).** They were credited to the owner at the owner's tier.
- **A rate limiter's 429 credited as the app refusing a stranger (row 58), then a crash credited the same way
  (row 62).** "Refused to somebody not signed in" was given when the app's own check never ran. Looking for every
  place that read an answer this way found 29 passes and five findings that a crash could produce (rows 62 and 63).
- **39 known vulnerabilities that were 20 (row 51).** One vulnerability published under two names was counted twice.
- **Coverage counted 18 requirements as checkable by a clean run (row 71)** when the 21 checks that speak to them
  only ever raise a finding. A review of the running-app checks found it; the reports themselves had been honest.
- **Ten false alarms and wrong statuses from another project's real use (rows 55 to 75).** A shell variable reported
  as a hard-coded password, `sv`'s own template flagged on every app, a hash-pinned `requirements.txt` called
  unpinned. Most told the owner to fix something that was right.

## What this shows

- **The characteristic error of a security checker is an overclaim, and tests do not find overclaims.** Nearly three
  in four corrections went down, and 73 of 76 were found by something other than a failing test: building the next
  thing, a person reading, review, another project using it, or real use. This is the same finding as `TOP10.md`'s
  A10 (verdicts that fail open) and `figure-how-caught.html`, measured from a different angle.
- **More checks meant more corrections, not fewer.** The two busiest days for corrections were days the test count
  rose most or `sv` met a new user. New checks brought new claims, and each claim was a new way to be wrong.
- **Honesty lowered the numbers.** Several corrections made a headline worse on purpose: coverage went down, "0
  findings" became "not run", "no" became "not assessed", and a refusal that was a rate limiter's or a crash's
  stopped counting. A tool whose numbers only rise over time is not necessarily improving.
- **Somebody else's use found what the builders did not.** Ten of the 28 corrections since 27 September came from
  another project using `sv` for its own ends. Earlier, nine came from the owner or real use, several from a plain
  question: why does a Python app score zero (row 11)? A user with no stake in how `sv` was built asks what its
  numbers mean, and that is one of the most effective checks the project had.

## Limits

- **Only corrections that were written down are here.** A number fixed without a note in a commit is missing, so
  this is a floor, not a count.
- **The "how it was found" groups are judgments,** made from each commit's own description, its pull request, and
  the backlog.
- **Three corrections from the morning of 28 September are new here** (rows 49 to 51). The first version stopped at
  27 September and did not include them.
- **Corrections to the paper's own numbers are not here.** The paper's files were corrected twice on 28 September
  (#385, #392); those are about the record of `sv`'s history, not about what `sv` told anyone.
- **v1's test counts are the figures stated in commit messages.** The 810 on 17 September comes from the first
  session's recorded reasoning (`securevibe-reasoning.md`, 20:04), because that day's commits were lost. `sv`'s
  counts are `#[test]` markers at the last commit on `main` each day.
- **Two v1 dates are when a fault was found, not when it was fixed:** row 16 was fixed on 24 September, and row 8 was
  finished in `868102fa`.
