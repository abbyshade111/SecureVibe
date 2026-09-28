# What the checks claimed, and what turned out to be true

SecureVibe's purpose is to tell a person what is and is not verified about their app. This is the record of every
time it told somebody something that was later found to be wrong: a number, a status, or a verdict reported to the
owner, printed in a report, counted in `docs/COVERAGE.md`, or stated in its own documents. Every correction is one
row of `corrections.csv`, with its date, what was claimed before, what it became, why, how it was found, and the
commit or pull request. The figure is `figure-corrections.html`.

## The count

**48 corrections in ten days, 16 in v1 and 32 in `sv`.**

| Direction | v1 | `sv` | Total |
|---|---|---|---|
| **Down:** the claim was stronger than the evidence | 7 | 25 | 32 |
| **Up:** the claim was weaker than the evidence | 6 | 5 | 11 |
| **Wording:** the claim was true, but read as something else | 3 | 2 | 5 |

Two out of three went down. A checker that errs tends to err toward telling people their app is safer than it is,
because every shortcut in a check (a tool that ran on nothing, a silence read as "no", a citation one digit off) makes
the report greener, never redder. Upward corrections were mostly v1 counting against requirements its apps met, and
`sv` failing to show checks it had actually made.

By day: 3 on 18 September, 5 on the 19th, 8 on the 20th, none on the 21st or 22nd, 1 on the 23rd, 7 on the 24th,
**14 on the 25th**, 6 on the 26th, and 4 on the 27th. The peak is the day `sv` added the most checks: its test count
more than doubled that day, from 326 to 687.

## How each was found

| How it was found | Corrections |
|---|---|
| Somebody read the output, the data, or a number, and it did not add up | 15 |
| The owner, or somebody using SecureVibe for real | 9 |
| Building or designing something else, which exposed it | 9 |
| One AI session reviewing another's merged work | 8 |
| Running a tool, or SecureVibe itself, on real input | 4 |
| **A failing test** | **2** |
| Not recorded | 1 |

These groups are a judgment from each commit's own account, and `corrections.csv` gives that account for every row.

**Two of 48 were caught by a test failing**:

- a TypeScript file that does not parse was being counted as clean (row 22);
- a sign-in that quietly failed could credit the signed-in guard (row 47).

Over the same days, `sv`'s tests grew from 54 to 1,306, and v1's server tests from 810 to 1,078:

| Day | `sv` tests (`#[test]`, last commit on `main` that day) | v1 server tests (as stated in commits) |
|---|---|---|
| 17 September | — | 810 |
| 19 September | — | 1,002 |
| 20 September | — | 1,078 |
| 22 September | 54 | — |
| 23 September | 161 | — |
| 24 September | 326 | — |
| 25 September | 687 | — |
| 26 September | 1,132 | — |
| 27 September | 1,306 | — |

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

## What this shows

- **The characteristic error of a security checker is an overclaim, and tests do not find overclaims.** Two of three
  corrections went down, and 46 of 48 were found by something other than a failing test: a person reading, real use,
  review, or building the next thing. This is the same finding as `TOP10.md`'s A10 (verdicts that fail open) and
  `figure-how-caught.html`, measured from a different angle.
- **More checks meant more corrections, not fewer.** The busiest day for corrections was the day the test count more
  than doubled. New checks brought new claims, and each claim was a new way to be wrong.
- **Honesty lowered the numbers.** Several corrections made a headline worse on purpose: coverage went down, "0
  findings" became "not run", and "no" became "not assessed". A tool whose numbers only rise over time is not
  necessarily improving.
- **Nine came from the owner or from real use, several from a plain question.** Why does a Python app score zero
  (row 11)? Will it hang (row 4)? The owner watching a build saw a feature called "Built" that drew nothing (row 7).
  The others came from real apps: the first outside app, and the owner's first builds with `sv`. A non-programmer
  asking what a number means was one of the most effective checks the project had.

## Limits

- **Only corrections that were written down are here.** A number fixed without a note in a commit is missing, so
  this is a floor, not a count.
- **The "how it was found" groups are judgments,** made from each commit's own description.
- **v1's test counts are the figures stated in commit messages.** The 810 on 17 September comes from the first
  session's recorded reasoning (`securevibe-reasoning.md`, 20:04), because that day's commits were lost. `sv`'s
  counts are `#[test]` markers at the last commit on `main` each day.
- **Two v1 dates are when a fault was found, not when it was fixed:** row 16 was fixed on 24 September, and row 8 was
  finished in `868102fa`.
