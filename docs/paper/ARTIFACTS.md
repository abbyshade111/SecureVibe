# Artifact index

Everything gathered for the paper, what it is, and what it is evidence *for*. Nothing here is an argument; the
files are the record and the reader can recompute anything in them.

## In this folder (`docs/paper/`, version-controlled)

| file | what it is |
|---|---|
| `TIMELINE.md` | The surviving record, 18–27 September 2026, by day: all 116 commits to 17:32 on 20 September, then each of the 267 changes that reached `main` (226 of them pull requests), with times and subjects. |
| `figure-timeline.html` | The whole project on one page: v1 and `sv` as two lanes, eight numbered milestones, and commits per day, with the same numbers as tables beneath. |
| `figure-security.html` | Security across both versions: v1's three-arm result, how far `sv`'s checks reach (ASVS 53 → 132 in 34 hours, from every version of `docs/COVERAGE.md`), where that reach stands by framework and level, and the two approaches side by side. |
| `figure-cost.html` | Cost and speed: v1's cost and time per run type, where its $63.46 went, what made it cheaper, and four measured speed-ups across both versions. |
| `figure-usability.html` | What people hit that the tests did not: v1's 13, and `sv`'s 18 from the owner's first build, the start from an empty folder, and VS Code, each with its fix. |
| `figure-how-caught.html` | How the faults the tests missed were caught: by use, by one session reviewing another, by breaking a guard on purpose, by v1's harness, or by accident; and how parallel sessions coordinated. |
| `TOP10.md` | The project's security faults against the OWASP Top 10:2025: weaknesses in SecureVibe's own code (18), its verdicts that failed open (8, all A10), v1 checking itself (195 findings, 160 false alarms), and what it found in the apps it checked. Each item is mapped through a CWE on the category's official list, with its source. |
| `figure-top10.html` | The same, as one grid: the ten categories against the four kinds of evidence. |
| `AGENTIC.md` | The project against the OWASP Top 10 for Agentic Applications (2026): v1's own AI agents, `sv` driven by an AI coding tool over MCP, `sv`'s checks of other apps' AI features, and the project built by several AI sessions at once. 16 incidents, 15 defenses, and 7 checks, each placed by judgment against the risk descriptions, with its source. |
| `figure-agentic.html` | The same, as one grid: the ten agentic risks against the four lenses. |
| `SELF-ASSESSMENT-V2.md` | `sv` checking itself on 27 September: how it was run, both runs (the whole repository, 804 findings; the product code, 252), every product finding triaged (191 false alarms, 61 accepted, 0 real), what it cannot see, and the comparison with v1's self-assessment. |
| `self-assessment-v2/` | The reports `sv` wrote for both runs (`repository/`, `product-only/`), the product run's file list, and `triage.json` with a verdict and reason for each of its 252 findings. |
| `figure-self-assessment.html` | Each version checking itself: v1's 195 findings and `sv`'s 252 (product code), by how a person triaged them. False alarms were 82% and 76%; v1 had 2 real findings, fixed that evening, and `sv` none. |
| `ADRS.md` | The architecture decision records of both versions: when each was written, what happened to it, what the later evidence says, how v1's decisions carried into `sv`, a check of every citation (15 of 16 fit), and eight inconsistencies, each now in the backlog. |
| `figure-adrs.html` | Every record as a line from the day it was written to 27 September: matching what was built, decided but not yet written, or out of step with what was built. |
| `CORRECTIONS.md` | Every time SecureVibe's reported numbers or verdicts were later found to be wrong: 48 corrections in ten days, 32 of them downward, set against the test count at the time. Two of the 48 were caught by a failing test. |
| `corrections.csv` | 48 rows, one per correction: date, version, direction, how it was found, the claim before and after, why, and the commit or pull request. |
| `figure-corrections.html` | The same, as three charts: corrections by day and direction, tests over the same days, and how each correction was found. |
| `DECISIONS.md` | The 23 decisions that shaped the project, each with who proposed it and who made the final call, quoted from the session transcripts: the owner chose 19, an AI session 3, and one was split. The owner took Claude's recommended option in 24 of 29 questions. |
| `figure-decisions.html` | The same, as a grid of who proposed against who chose, with every decision in its cell, and the 29 recommendations as a row of squares. |
| `COORDINATION.md` | What running several AI sessions at once cost and bought, 18–28 September: 93 of 469 changes to `main` only claimed or released work, 56 conflicts were resolved by hand (31 in the backlog alone), 14 duplicates and collisions, 3 pull requests thrown away, and 28 faults found by one session reviewing another's work. |
| `coordination.csv` | 209 rows, one per event: claims, unmerged pull requests, conflicts, duplicates, collisions, and faults found in review, each with its source. |
| `figure-coordination.html` | The same, as three charts: changes to `main` per day with the coordination share, conflicts per day, and how the project's faults were found. |
| `TESTS-AND-FAULTS.md` | Test growth against fault discovery: 149 faults in SecureVibe's own code, how each was found (5 of the 129 in the product by a failing test), the rate per 1,000 lines changed as the suites grew, and whether each fix added a test (104 of 119). |
| `faults.csv` | 144 rows covering the 149 faults: when and how each was found, when fixed, whether the fix added a test, and the commit or pull request. |
| `tests_by_day.csv` | Tests, tests added, faults found, and lines changed, per day and version. |
| `figure-tests-faults.html` | The same, as tests per day, faults per day with the rate per 1,000 lines, and the 119 fixes that did or did not leave a test behind. |
| `METHODOLOGY.md` | What a run does, the frameworks and their counts, the evidence model, the comparison design, stated limits. |
| `figure-three-arms.html` | The outcome figure: requirements by evidence strength across the three arms, with the table beneath it. |
| `requirements.csv` | 1,035 rows — every ASVS and AISVS requirement, per arm, with its status, the evidence types behind it and how many pieces. |
| `findings.csv` | 38 rows — every finding raised across the three arms, with rule id, severity, file and which scanner raised it. |

## On the USB drive (`securevibe-checks/`)

| folder | what it is |
|---|---|
| `2026-09-20_comparison/` | The three arms. Each holds `reports/` as SecureVibe wrote them, `run-logs/` with every stage log and the full event stream, `project.json` with the wizard answers, and for A and C the source as checked. 15 MB, 144 files. |
| `2026-09-20_comparison/RESULTS.md` | The comparison table and what it shows, including the caveat about Arm B's headline. |
| `2026-09-20_FitnessTracker_uploaded/` | The *first* Python run, before the day's reporting fixes — the one that said "0 of 106 verified". Kept deliberately as the before-state, with a README explaining why its numbers are wrong. |
| `SecureFit-app-2026-09-20/` | The exact source uploaded for Arm B, 200 files, secrets removed. Byte-identical to Arm A's code. |

## The evidence breakdown

The single table most worth reproducing, computed from `requirements.csv`. Counts are pieces of evidence
gathered, not requirements:

| evidence type | tier | Arm A (native) | Arm B (same code, uploaded) | Arm C (Python, uploaded) |
|---|---|---|---|---|
| test | **strong** | 82 | 0 | 0 |
| runtime probe (dast) | **strong** | 58 | 0 | 0 |
| template control | medium | 114 | 0 | 0 |
| configuration check | medium | 25 | 16 | 10 |
| scanner | medium | 10 | 9 | 9 |
| AI review | weak | 0 | 55 | 0 |
| **total** | | **289** | **80** | **19** |

Arm A gathered 140 pieces of strong evidence. Arms B and C gathered none, and no amount of scanning or AI review
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
