# More tests, fewer surprises?

Both versions of SecureVibe grew large test suites quickly: v1 from 810 to 1,078 tests in four days, `sv` from 54 to
1,341 in a week. This sets that growth beside every fault found in SecureVibe's own code, and asks whether more
tests meant fewer faults got through, how the faults that got through were found, and whether the suite learned from
each one. Every fault is one row of `faults.csv`, with when and how it was found, whether the fix added a test, and
its source. The day-by-day figures are in `tests_by_day.csv`, and the figure is `figure-tests-faults.html`.

**The short answer is no.** The rate of faults held steady while `sv`'s suite grew fourfold. What predicted faults
was how much new code was written that day, and how much people used it. Almost every fault the tests missed did get
a test when it was fixed.

## The faults

**149 faults in twelve days: 81 in v1 and 68 in `sv`.** A fault here is anything in SecureVibe's own code or checks
that was found, has a named source, and was fixed: a bug, a crash, a security weakness, a wrong result, or a verdict
that failed open. Feature work, speed-ups, pure formatting fixes, and wrong claims in documents are left out (those
are in `CORRECTIONS.md`). 129 of the 149 were in the product; the other 20 were tests that were weak or broken, which
matters because a test that cannot fail guards nothing.

| How it was found | v1 | `sv` | Total |
|---|---|---|---|
| Another session reviewing the work | 10 | 18 | 28 |
| The owner, or real use | 20 | 6 | 26 |
| Running it on real input | 11 | 10 | 21 |
| Building or designing something else | 9 | 10 | 19 |
| v1's evaluation harness | 14 | — | 14 |
| An automated tool in CI (CodeQL, clippy, lints) | 11 | 2 | 13 |
| Breaking a guard on purpose, to see which tests fail | 2 | 8 | 10 |
| **A failing test** | **1** | **8** | **9** |
| Not recorded | 3 | 6 | 9 |
| **Total** | **81** | **68** | **149** |

**Of the 129 faults in the product, 5 were caught by a failing test.** Breaking a guard on purpose, the practice
`CLAUDE.md` asks for, found 10 faults, and all 10 were in the tests: a guard caught by only one test, or a test that
passed whatever the code did. That is what it is for. It checks the tests, not the product.

The 22 verdicts that failed open, telling someone something was verified when it was not, were found by the owner's
use (6), review (6), building something else (4), a failing test (2), real input (2), and not recorded (2).

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
| 28 September, to 16:18 | `sv` | 1,341 | 12,200 | 6 | 3 | 0.5 |

v1 also had 14 faults found from 23 to 26 September, in light maintenance after `sv` began; they are in the files.
v1's test counts are the figures stated in its commits (17 September's from the first session's own record). `sv`'s
are the tests on `main` at the last change of each day. Lines changed leave out documents, data, lockfiles, and the
two large moves of files.

## Does a pattern hold?

These are descriptions of eleven days, not a test of anything, and several sessions were working at once.

- **The rate did not fall as the suite grew.** On every full `sv` day from the 24th, it found between 0.5 and 1.2
  faults per 1,000 lines changed, while the suite grew from 320 tests to 1,306.
- **Faults followed code written.** In `sv`, the days with more lines changed found more faults (a rank correlation of
  0.90 across seven days).
- **Faults followed use.** v1's 19 and 20 September found 55 of its 81 faults, at seven to ten times the rate of
  the day before, and 38 of those 55 came from the owner's use, review by another session, or real input rather than
  from anything automated. Use and code changed together, so this is a judgment.
- **`sv`'s tests did catch more.** 16 of its 68 faults were found by a failing test or by breaking a guard, against 3
  of v1's 81. But 12 of those 16 were faults in the tests themselves, so for faults in the product the difference is
  small: 4 of 54 in `sv`, 1 of 75 in v1.

## Did the suite learn from each surprise?

**Mostly, yes.** Of the 124 faults in the product that the tests missed, 119 can be checked (the other five were
fixed in 17 September's history, which was lost). **The fixing commit added or changed a test for 104 of the 119
(87%)**: 56 of 69 in v1 (81%), and 48 of 50 in `sv` (96%). 93 of those added a new test. The two in `sv` without one
were a clean-up after files moved, and a check that runs as a Python script rather than a Rust test.

So each surprise made the suite larger. It did not make the next surprise less likely, because the next one was
somewhere the suite had not been told to look.

## What this shows

- **Tests confirm what someone thought of, and the faults were in what nobody had thought of.** A fault that a test
  can catch is one whose shape was known when the test was written. Almost all of the 149 were found by a person or a
  process looking at the whole: using it, reviewing it, running it on something real, or building the next thing.
- **A growing suite is not a sign of falling risk.** `sv`'s suite grew fourfold from 24 September, and the rate of
  faults per line of new code stayed flat. The count of tests measures effort, not safety.
- **The suite still earned its keep.** 87% of the faults that got through left a test behind, so none of them came
  back. That is protection against regression, which is what a test suite is good at.
- **This is the same finding as the corrections ledger, from the other side.** `CORRECTIONS.md` found that 2 of 48
  wrong claims were caught by a failing test; here, 5 of 129 product faults were.

## Limits

- **"Found" is often the time of the fix.** Where no earlier report exists, the fault's found time is the fixing
  commit's, so the time between finding and fixing is zero for most rows.
- **How each fault was found is a judgment,** made from the commit message; nine rows record no finder.
- **One commit can fix several faults,** and they share its answer about whether a test was added: one v1 commit added
  one test for seven faults.
- **Only faults that were fixed are here.** Faults found and left open, and faults never found, are not. One
  exception is counted: V1-06, the CI hang, was fixed only on a branch that never merged, so v1 as archived still
  has it.
- **v1's counts from 23 September on** are a static count of test calls in the code, which runs 60 to 160 below the
  numbers stated in its commits; they are in `tests_by_day.csv`, not in the table above.
- **Eleven days is a small sample,** and the busiest days had the most sessions, the most code, and the most use at
  once, so none of these can be separated from the others.
