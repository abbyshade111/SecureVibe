# Artifact index

Everything gathered for the paper, what it is, and what it is evidence *for*. Nothing here is an argument; the
files are the record and the reader can recompute anything in them.

## In this folder (`docs/paper/`, version-controlled)

The documents run to the cut-off, `main` at `157ddc3` (Merge PR #564, 11:37 Eastern on 4 October 2026); each says so,
and where a number has changed since its first version (mostly 27 to 29 September), it gives both. The v1 comparison
files (`figure-three-arms.html`, `requirements.csv`, `findings.csv`) are v1's fixed record of 20 September and are not
updated. What changed in `sv` after the cut-off is in one file, `SINCE-THE-CUTOFF.md`, which the others point to; the
trials run after it, 5 to 8 October, are in `TRIALS.md`.

| file | what it is |
|---|---|
| `SINCE-THE-CUTOFF.md` | What changed in `sv` after the cut-off: to `main` at `4c3c5e0` (16:30 on 4 October), 41 more pull requests, 14 of the deep review's 58 findings fixed, `sv review` and ADR-026, 1,761 tests; and, added on 8 October, to `main` at `01b10f60`: 378 more pull requests, all 58 findings done, 42 decision records, 2,366 tests, the install step, the record checks and the nine statuses, and what that means for re-running the comparison study. |
| `TRIALS.md` | The ten trials of 5 to 8 October 2026: 485 builds by Claude Sonnet 5.5, Claude Haiku 4.5 and, in the tenth, Claude Haiku 5.5, $156.69, each to a protocol fixed before any build. Whether `sv` attached while building makes an app testable, and whether a library prompt pasted into the request removes the problem it is for: 10 of 21 comparisons shown, 4 not shown, 7 with no reading. What they changed in `sv`, and what they cannot show. |
| `figure-trials.html` | The same: every pasted-prompt comparison as the share of builds with the problem without and with the prompt, the trials' sizes and costs, and both as tables. Made from the trials' committed results by `trials/make_figure.py`. |
| `trials/make_figure.py` | Writes `figure-trials.html` from `docs/prompts/library-trial/`'s results files; only the trials' sizes and costs are typed in, each from its write-up. |
| `TIMELINE.md` | The surviving record, 18 September to 4 October 2026, by day: 1,784 commits in all; the 116 to 17:32 on 20 September, then each of the 569 changes that reached `main` (528 of them pull requests), with times and subjects. |
| `figure-timeline.html` | The whole project on one page: v1 and `sv` as two lanes, twelve numbered milestones, and commits per day, with the same numbers as tables beneath. |
| `HOW-SV-WORKS.md` | A short account of how `sv` works, drawn from `main` on 29 September and redrawn at the cut-off, with what changed between the two. |
| `figure-how-sv-works.html` | The same, as one diagram: what goes in, the stages of a check, and what comes out. |
| `figure-security.html` | Security across both versions: v1's three-arm result, how far `sv`'s checks reach (ASVS 53 → 163 of 345, 25 September to 3 October, from every version of `docs/COVERAGE.md`), where that reach stands by framework and level, and the two approaches side by side. |
| `OPTIMIZATION.md` | Cost and speed: v1's AI spend over 18–20 September ($63.46, 823 calls), what made it cheaper, and `sv`'s measured speed-ups and time limits, 27 September to 4 October. |
| `figure-cost.html` | The same: v1's cost and time per run type, where its $63.46 went, what made it cheaper, and measured speed-ups across both versions. |
| `figure-usability.html` | What people hit that the tests did not: v1's 13, `sv`'s from the owner's first build, the start from an empty folder, and VS Code, and from 28 September 31 problems hit by use (16 fixed by the cut-off), each with its fix. |
| `figure-how-found.html` | v1's usability failures, 18–20 September, and what found them: 13 by people, none by its 1,078 server and 215 template tests at `v1-paper`. |
| `figure-how-caught.html` | How the faults the tests missed were caught: by use, by one session reviewing another, by breaking a guard on purpose, by v1's harness, by accident, by another project using `sv`, and by the outside review of 4 October. |
| `TOP10.md` | The project's security faults against the OWASP Top 10:2025: weaknesses in SecureVibe's own code (49; 18 to 27 September), its verdicts that failed open (43, all A10; 8 to 27 September, 30 from the deep review), each version checking itself (v1 195 findings, 160 false alarms; `sv` 252 on 27 September and 479 on 4 October), and what `sv` found in the five apps of the comparison study (62 in their own code). Each item is mapped through a CWE on the category's official list, with its source. |
| `figure-top10.html` | The same, as one grid: the ten categories against the four kinds of evidence. |
| `AGENTIC.md` | The project against the OWASP Top 10 for Agentic Applications (2026): v1's own AI agents, `sv` driven by an AI coding tool over MCP, `sv`'s checks of other apps' AI features, and the project built by several AI sessions at once. 24 incidents, 21 defenses, 25 checks, and 13 items open at the cut-off (16, 15, 7, and 1 to 27 September), each placed by judgment against the risk descriptions, with its source. |
| `figure-agentic.html` | The same, as one grid: the ten agentic risks against the four lenses. |
| `SELF-ASSESSMENT-V2.md` | `sv` checking itself, twice. On 27 September: the whole repository, 804 findings; the product code, 252, triaged as 191 false alarms, 61 accepted, and 0 real (4 real in hindsight). On 4 October: the repository, 1,162; the product code, 479, triaged as 413 false alarms, 60 accepted, and 6 real, all deep-review items. With what it cannot see and the comparison with v1's self-assessment. |
| `self-assessment-v2/` | The reports `sv` wrote on 27 September for both runs (`repository/`, `product-only/`), the product run's file list, and `triage.json` with a verdict and reason for each of its 252 findings. |
| `self-assessment-v2/2026-10-04/` | The same for the run of 4 October, laid out the same way: `triage.json` covers its 479 product findings. |
| `figure-self-assessment.html` | Each version checking itself: v1's 195 findings, and `sv`'s 252 (27 September) and 479 (4 October) in product code, by how a person triaged them. False alarms were 82%, 76%, and 86%; v1 had 2 real findings, fixed that evening, `sv` none as triaged on 27 September and 6 on 4 October. |
| `ADRS.md` | The architecture decision records of both versions, 27 in all (13 of v1's, 11 of `sv`'s, 3 of the template's): when each was written, what happened to it, what the later evidence says, how v1's decisions carried into `sv`, a check of every citation (15 of v1's 16 fit), and eight inconsistencies, all resolved. |
| `figure-adrs.html` | Every record as a line from the day it was written to 4 October: matching what was built, decided but not yet written, or out of step with what was built. |
| `CORRECTIONS.md` | Every time SecureVibe's reported numbers or verdicts were later found to be wrong: 76 corrections (48 to 27 September), 55 of them downward, set against the test count at the time. Three of the 76 were caught by a failing test. |
| `corrections.csv` | 76 rows, one per correction: date, version, direction, how it was found, the claim before and after, why, and the commit or pull request. |
| `figure-corrections.html` | The same, as three charts: corrections by day and direction, tests over the same days, and how each correction was found. |
| `DECISIONS.md` | The 36 decisions that shaped the project (23 to 28 September), each with who proposed it and who made the final call, quoted from the session transcripts or, after 28 September, the backlog and pull requests: the owner chose 32, an AI session 3, and one was split. The owner took Claude's recommended option in 28 of 35 questions. |
| `figure-decisions.html` | The same, as a grid of who proposed against who chose, with every decision in its cell, and the 35 recommendations as a row of squares. |
| `COORDINATION.md` | What running several AI sessions at once cost and bought, 18 September to 4 October: 172 of 655 changes to `main` only claimed or released work (93 of 469 to 28 September), 103 conflicts were resolved by hand (55 in the backlog), 16 duplicates and collisions, 3 pull requests thrown away of 564, and 40 faults found by one session reviewing another's work. |
| `coordination.csv` | 359 rows, one per event: claims, unmerged pull requests, conflicts, duplicates, collisions, work sent between sessions, and faults found in review, each with its source. |
| `figure-coordination.html` | The same, as three charts: changes to `main` per day with the coordination share, conflicts per day, and how the project's 255 faults were found. |
| `TESTS-AND-FAULTS.md` | Test growth against fault discovery: 255 faults in SecureVibe's own code (149 to 28 September), 196 fixed and 59 open at the cut-off, how each was found (7 of the 230 in the product by a failing test), the rate per 1,000 lines changed as the suites grew (`sv` 1,655 tests at the cut-off), and whether each fix added a test (141 of 159). |
| `faults.csv` | 254 rows: 249 counted, which stand for the 255 faults, and 5 not counted (2 the review marked plausible, a limit, and 2 that name no fault in `sv`): when and how each was found, when fixed, whether the fix added a test, and the commit or pull request. |
| `tests_by_day.csv` | Tests, tests added, faults found, and lines changed, per day and version, to 4 October. |
| `figure-tests-faults.html` | The same, as tests per day, faults per day with the rate per 1,000 lines, and the 159 fixes that did or did not leave a test behind. |
| `STUDY.md` | The comparison study, 29 September to 3 October: `sv` run on five AI-built apps under identical conditions, recomputed from the study's raw output. 422 findings, 62 of them in the apps' own code; the ten `sv` issues it raised, all fixed on `main`. |
| `study.csv` | 606 rows, one per app, run, and measure, each with its source. |
| `figure-study.html` | The same, as charts per app: where the findings were, own-code findings per 1,000 lines, what the requirements came to, and family-hub as built. |
| `REVIEW.md` | The deep review of `sv` at `eff3f17` on 4 October: 58 findings (1 critical, 26 high, 22 medium, 9 low), how they were found, and what was done by the cut-off: S1 fixed (#555), S2 to S5 and S12 claimed, S2 to S5 in open pull requests #558 and #562 (both merged shortly after; `SINCE-THE-CUTOFF.md`). |
| `review.csv` | 58 rows, one per finding: part, severity, how it was confirmed, its state at the cut-off, and its backlog entry. |
| `figure-review.html` | The same, one square per finding, by part and severity, marked by its state at the cut-off. |
| `METHODOLOGY.md` | What a v1 run does, the frameworks and their counts (AISVS 191, and 68 in Appendix C), the evidence model, the comparison design, what checks the checker (v1: 1,078 server tests at `v1-paper`; `sv`: 1,655 at the cut-off), and stated limits. |
| `figure-three-arms.html` | The outcome figure: requirements by evidence strength across the three arms, with the table beneath it. |
| `requirements.csv` | 1,035 rows — every ASVS requirement (345 for each of the three arms), with its status, the evidence types behind it and how many pieces. (Until 4 October this said "every ASVS and AISVS requirement"; it holds no AISVS rows.) |
| `findings.csv` | 38 rows — every finding raised across the three arms, with rule id, severity, file and which scanner raised it. |

## Outside the repository (on the owner's machine)

The scripts that rebuild the CSVs and figures, and the working data they read, are not in the repository. They are
on the owner's machine at `~/code/sv-paper-data/`: `scripts/` holds the rebuild scripts, `selfcheck/`
the working files of `sv`'s self-checks, and `prs.json` the pull-request record (all 565 pull requests, fetched
4 October at 11:39, of which #1 to #564 were opened by the cut-off). The comparison study's pipeline, runs, and Word
report, and the deep review, are in the owner's other project at `~/code/sv-study/`.

## On the USB drive (`securevibe-checks/`)

| folder | what it is |
|---|---|
| `2026-09-20_comparison/` | The three arms. Each holds `reports/` as SecureVibe wrote them, `run-logs/` with every stage log and the full event stream, `project.json` with the wizard answers, and for A and C the source as checked. 15 MB, 144 files. |
| `2026-09-20_comparison/RESULTS.md` | The comparison table and what it shows, including the caveat about Arm B's headline. |
| `2026-09-20_FitnessTracker_uploaded/` | The *first* Python run, before the day's reporting fixes — the one that said "0 of 106 verified". Kept deliberately as the before-state, with a README explaining why its numbers are wrong. |
| `SecureFit-app-2026-09-20/` | The exact source uploaded for Arm B, 200 files, secrets removed. Byte-identical to Arm A's code. |

## Citation tags

The paper cites v1 by the tags `v1-paper` (the comparison of 20 September), `v1-paper-doi`, and `v1-final` (v1 as
archived), and by its Zenodo version DOI, 10.5281/zenodo.22984709. All three tags are in this repository.

## The evidence breakdown

The single table most worth reproducing, computed from `requirements.csv`. Counts are requirements carrying each type
of evidence; one requirement can carry several. (Until 4 October this said they were pieces of evidence; the file's
`evidence_count` column, which counts pieces, sums to 505, 81, and 19.)

| evidence type | tier | Arm A (native) | Arm B (same code, uploaded) | Arm C (Python, uploaded) |
|---|---|---|---|---|
| test | **strong** | 82 | 0 | 0 |
| runtime probe (dast) | **strong** | 58 | 0 | 0 |
| template control | medium | 114 | 0 | 0 |
| configuration check | medium | 25 | 16 | 10 |
| scanner | medium | 10 | 9 | 9 |
| AI review | weak | 0 | 55 | 0 |
| **total** | | **289** | **80** | **19** |

In Arm A, 101 requirements had strong evidence (82 from a test, 58 from a runtime probe, some from both). Arms B and C
had none, and no amount of scanning or AI review
can produce any, because strong evidence in this model means the app was *run* — a test executed, a live request
refused. That is the whole of the 104-to-0 difference, and it is a property of the method rather than of the code.

## Reproducing the numbers

    # requirement statuses per arm
    python3 -c "import csv,collections;rows=list(csv.DictReader(open('requirements.csv')));\
    print(collections.Counter((r['arm'],r['status']) for r in rows if r['standard']=='ASVS'))"

    # findings by severity per arm
    python3 -c "import csv,collections;rows=list(csv.DictReader(open('findings.csv')));\
    print(collections.Counter((r['arm'],r['severity']) for r in rows))"

## What is deliberately not here

- Any `.env`, key, certificate or one-time password. The exports strip them; the uploader strips them again.
- The AI review's prompts and raw responses. `workspace/llm-audit.jsonl` records every call and its cost and
  stays on the owner's machine.
- Arm A with an AI review. SecureVibe offers a native app an AI review only as part of a full rebuild, which
  costs about $3.75 and rewrites the code. Arm A's AI figures in the paper should come from the separate full
  build of 19 September (132 of 192 requirements reviewed, 231 citations, $3.75) and be labeled as a different
  run against slightly older code.
