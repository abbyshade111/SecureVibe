# Artifact index

Everything gathered for the paper, what it is, and what it is evidence *for*. Nothing here is an argument; the
files are the record and the reader can recompute anything in them.

## In this folder (`docs/paper/`, version-controlled)

| file | what it is |
|---|---|
| `TIMELINE.md` | All 116 commits, 18–20 September 2026, with times and subjects, grouped by day. |
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
  build of 19 September (132 of 192 requirements reviewed, 231 citations, $3.75) and be labelled as a different
  run against slightly older code.
