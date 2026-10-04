# Five AI-built apps under one `sv`: the comparison study

From 29 September to 3 October 2026 the cato-pipeline session, at the owner's asking, ran `sv` over five apps built
with AI coding tools, under conditions held identical for all five, and wrote the results up in a Word report
(`sv-comparison-2026-09-29.docx`, updated 3 October). This document is the paper's account of that study. Every
number in it was recomputed from the study's raw output, not copied from the report, and where the two differ it
says which is right and why. One row per app and measure is in `study.csv`; the figure is `figure-study.html`.
The record runs to `main` at `157ddc3` (Merge PR #564, 4 October 2026, 11:37 Eastern).

## The question

What does `sv` say about apps that people really built with AI tools, when each app is treated exactly alike? And
how much of what it says is about the app's own code, rather than its tests, the libraries copied into it, or the
way the study was run? The same pipeline also measured code quality, placed each security finding in the OWASP Top
10:2025, and measured ten categories of issue that a published report found common in AI-written code.

## The apps

| App | What it is | Commit | Commits in its history | Scanned |
|---|---|---|---|---|
| Fitness Tracker | Python and JavaScript | `b49ed8f` | 1 | whole repository |
| Health tracker (built for a friend) | Python (FastAPI) and JavaScript | `e9481dc` | 65 | whole repository |
| SecureFit | TypeScript | `b5a2230` | 1 | `app/` only |
| my-first-app | JavaScript (Node.js) | `1a964c4` | 1 | whole repository |
| family-hub | Python (Flask) | `4577a8e` | 5 | whole repository |

The first four were pinned on 29 September, family-hub on 3 October. SecureFit was scanned at `app/` so that the
reports an earlier SecureVibe run left in its repository were not read as part of the app. family-hub was the only
app built with `sv` in the loop, by the owner, on 3 October.

## Method

- **A blank manifest for every app.** `sv` needs a `securevibe.toml` that says what the app is. Each app got `sv`'s
  own blank template, exactly as `sv init` printed it at `982f97e` (SHA-256 `d47b2776…`), with only the name and
  languages filled in. Everything else was left unanswered, or at the template's defaults (audience `customers`,
  deployment `internet`). Three apps had a manifest of their own (the health tracker, my-first-app, family-hub); it was
  replaced in the scanned copy only. family-hub's also carried 25 false-alarm reviews signed by the owner, which the
  blank template drops; they come back in the as-built comparison below.
- **`sv` and Bandit, offline.** `sv report --tools --advisories` from SecureVibe's published image at `982f97e`, with
  Bandit 1.9.4 added (Bandit is a Python security checker that `sv` runs and reads). The image was pinned by digest.
  The pipeline ran in a local CI server with no network route except to a local mirror. The apps were never started
  (no `--run`), so nothing that needs a running app was checked.
- **A pinned advisory snapshot.** Known vulnerabilities came from the mirror's exports of the OSV database for PyPI
  and npm. Each run resolved "latest" to a fixed digest once and recorded it.
- **A control.** The pipeline ran eleven times as it was built up. Its `same.py` compares two runs on every finding's
  fingerprint, the checks' states, the requirement counts, the undecided requirements, and the threats. Recomputed
  for this document: runs 4 to 10 each agree with run 11 on every app they contain, and run 10 and run 11 agree on all
  five. Runs 2 and 3 differ from run 11 for the health tracker only, because of a fault in `sv` the study found (item 4
  below): a folder given as `…/app/.` left Bandit's 151 file paths absolute and changed their fingerprints. The study
  also records a direct run of `sv` on the owner's Mac, independent of the pipeline, agreeing with run 4 fingerprint
  for fingerprint. That run's output is not among the files kept, so this document relies on the study's account of
  it.
- **Every finding in one class, by where it is.** *Own code*: the app's own code and configuration. *Tests*: test
  folders and files. *Vendored*: other people's code copied into the app (`vendor/`, `*.min.js`). *Dependencies*:
  advisories, the list of packages, and dependency manifests and lockfiles. *Method*: findings in the manifest the
  study put there, left out of every total. The rules are in the study's `compare.py` and covered by its tests.
- **Code quality** was measured on own code with three pinned tools: scc 4.1.0 (lines), lizard 1.24.0 (each
  function's complexity and length), and jscpd 5.3.3 (duplicated blocks of 50 or more tokens).
- **OWASP Top 10:2025.** Each finding was placed in one category through its CWE, using OWASP's own list of CWEs for
  each category. Bandit's findings reach `sv`'s report without a CWE, so Bandit's own CWE for each check was used; the
  five apps raise 23 different Bandit checks, and all 23 are in the study's table of Bandit's CWEs.
- **The ten AI-code issue categories** came from a report the owner supplied. They were measured with stand-ins on
  own code, per 1,000 lines: ruff 0.16.9 for Python and ESLint 10.11.0 for JavaScript and TypeScript, each with the
  study's rules; `sv`'s and Bandit's findings for security and severity; and, for formatting, the share of lines that
  differ from the common formatter settings that fit the app's own style best.

**How the numbers here were recomputed.** The study's `compare.py` was run again on run 11's raw reports and tool
output, into a fresh folder. It produced the same summary, byte for byte, as the one the pipeline published. The
family-hub variants were summarized the same way from the as-built reports. `study.csv` was then written from that
summary.

## Results

Severity is written critical / high / medium / low. Rates are per 1,000 lines of the app's own source code.

### `sv`'s findings

| | Fitness Tracker | Health tracker | SecureFit | my-first-app | family-hub |
|---|---|---|---|---|---|
| Findings in the app | 6 | 157 | 20 | 19 | 220 |
| … in own code | 4 | 10 | 16 | 8 | 24 |
| … in tests | 0 | 145 | 2 | 11 | 52 |
| … in vendored code | 0 | 0 | 0 | 0 | 142 |
| … about dependencies | 2 | 2 | 2 | 0 | 2 |
| **Own code by severity** | **0 / 2 / 1 / 1** | **0 / 0 / 7 / 3** | **0 / 2 / 14 / 0** | **0 / 0 / 8 / 0** | **0 / 9 / 6 / 9** |
| Own-code findings per 1,000 lines | 1.84 | 7.29 | 2.29 | 6.75 | 7.56 |
| … critical or high only | 0.92 | 0 | 0.29 | 0 | 2.84 |

Across the five apps, 422 findings: 62 in own code, 210 in tests, 142 in vendored code, and 8 about dependencies.
Each app also had one finding in the study's manifest (a commented example password in `sv`'s own template), left
out. None of the findings is critical.

- **Raw totals mislead.** The health tracker's 157 are 145 uses of Python's `assert` in its tests (Bandit B101).
  family-hub's 220 are mostly its committed copy of Flask (142) and its tests (52).
- **Own code, high.** The Fitness Tracker's two look real on their face: a database query built by joining text,
  and nothing stopping the environment file being committed. SecureFit's two are text that looks like a credential
  and is not (a form's error message and descriptive text). family-hub's nine are eight "SQL built by joining text"
  and one credential-like value, and the owner had already reviewed seven of the eight, and the credential, as
  false alarms (see the as-built comparison).
- **The medium findings concentrate in one rule per app**: SecureFit's 13 redirects to a destination built from a
  value (one of them inside its own safe-redirect helper), my-first-app's eight file paths built from a value.

### Dependency coverage

| | Fitness Tracker | Health tracker | SecureFit | my-first-app | family-hub |
|---|---|---|---|---|---|
| Known-vulnerability check | partly | partly | partly | ran | partly |
| Why not complete | package list incomplete | package list incomplete | package list incomplete | — | package list incomplete; 1 version could not be compared |

Only my-first-app, with a full `package-lock.json`, was compared package by package; nothing was found. Each of the
others fell short for its own reason: the Fitness Tracker's `requirements.txt` gives ranges, the health tracker has no
lockfile, and SecureFit's `tests/package.json` is unpinned. family-hub's shortfall was `sv`'s: its fully
hash-pinned `requirements.txt` and its `pylock.toml` were not read as lockfiles, and `sv` could not compare werkzeug
3.1.9 with three advisories whose ranges begin at a Python pre-release (items 8 and 9 below).

### Requirements not verified

| | Fitness Tracker | Health tracker | SecureFit | my-first-app | family-hub |
|---|---|---|---|---|---|
| Requirements that apply | 196 | 185 | 254 | 207 | 217 |
| … need attention | 5 | 5 | 6 | 3 | 10 |
| … checked automatically | 9 | 9 | 1 | 10 | 2 |
| … not verified by anything | 182 (92.9%) | 171 (92.4%) | 247 (97.2%) | 182 (87.9%) | 188 (86.6%) |
| Could not be placed | 257 | 258 | 188 | 230 | 236 |
| Tests `sv` suggests writing | 116 | 110 | 80 | 116 | 123 |
| Threats: found / not verified / checked in part / cannot place | 3 / 10 / 1 / 28 | 3 / 11 / 1 / 27 | 3 / 22 / 0 / 17 | 2 / 15 / 2 / 21 | 3 / 11 / 0 / 28 |

"Could not be placed" means nobody has answered the question that decides whether a requirement applies, which is
what a blank manifest does. The rest of each app's applicable requirements are ones its own `security-notes.md`
answers (family-hub 17), or, for my-first-app, 12 that its AI coding tool answered in its `security-notes.md` and
that `sv` counts as the tool's word, weaker than the owner's. Under this method, 87% to 97% of
what applies is verified by nothing, for every app. `sv` says so in each report: "Nothing in there says a
requirement passed, because nothing here can establish that."

### Code quality (own code)

| | Fitness Tracker | Health tracker | SecureFit | my-first-app | family-hub |
|---|---|---|---|---|---|
| Source lines | 2,169 | 1,371 | 6,973 | 1,185 | 3,173 |
| Lines in tests / vendored | 0 / 582 | 939 / 0 | 5,402 / 0 | 632 / 0 | 1,714 / 33,270 |
| Test lines per line of code | 0 | 0.68 | 0.77 | 0.53 | 0.54 |
| Comment ratio | 4.4% | 1.5% | 10.0% | 6.2% | 8.1% |
| Functions | 92 | 62 | 630 | 105 | 216 |
| Complexity: mean / max | 3.02 / 23 | 4.23 / 15 | 2.94 / 67 | 2.81 / 21 | 2.69 / 17 |
| Functions with complexity above 10 | 3 | 6 | 26 | 2 | 4 |
| Functions over 50 lines | 3 | 3 | 7 | 2 | 0 |
| Duplicated lines | 18 (0.7%) | 21 (1.3%) | 327 (3.9%) | 0 | 102 (2.5%) |

The Fitness Tracker has no tests. SecureFit has the most code, the most complex outliers, and the most duplication.
family-hub has the lowest mean complexity and no function over 50 lines, and combines the cleanest structure by
these measures with the most security findings under this method.

### OWASP Top 10:2025

All app findings, with own code in brackets. Categories with no finding in any app (A02 Security Misconfiguration,
A09 Security Logging and Alerting Failures) are left out of the table.

| Category | Fitness Tracker | Health tracker | SecureFit | my-first-app | family-hub |
|---|---|---|---|---|---|
| A01 Broken Access Control | 2 (2) | 2 (2) | 13 (13) | 19 (8) | 9 (6) |
| A03 Software Supply Chain Failures | 2 (0) | 2 (0) | 2 (0) | 0 | 2 (0) |
| A04 Cryptographic Failures | 0 | 0 | 0 | 0 | 15 (0) |
| A05 Injection | 1 (1) | 5 (5) | 0 | 0 | 71 (11) |
| A06 Insecure Design | 0 | 2 (2) | 1 (1) | 0 | 0 |
| A07 Authentication Failures | 0 | 0 | 4 (2) | 0 | 54 (7) |
| A08 Software or Data Integrity Failures | 0 | 0 | 0 | 0 | 3 (0) |
| A10 Mishandling of Exceptional Conditions | 0 | 145 (0) | 0 | 0 | 64 (0) |
| CWE on no 2025 list | 0 | 0 | 0 | 0 | 2 (0) |
| No CWE at all | 1 (1) | 1 (1) | 0 | 0 | 0 |

In own code, across the five apps, 31 findings fall under A01, 17 under A05, 9 under A07, 3 under A06, and 2 carry
no CWE (the missing security contact). A01 is mostly redirects and file paths built from a value; A05 is mostly
family-hub's eight SQL findings. Most of A10 is `assert` in tests. **A zero is not a clean bill**: without starting
the app, a scan sees little of A01, almost nothing of A06 beyond configuration, and little of A09.

### The ten AI-code issue categories

Own code, per 1,000 lines, with counts in brackets.

| Category | Fitness Tracker | Health tracker | SecureFit | my-first-app | family-hub |
|---|---|---|---|---|---|
| 01 Issues overall | 8.76 (19) | 10.94 (15) | 13.05 (91) | 29.54 (35) | 10.40 (33) |
| 02 Critical and major issues | 0.92 (2) | 0 (0) | 0.29 (2) | 0 (0) | 2.84 (9) |
| 03 Logic and correctness | 0.92 (2) | 0 (0) | 0.29 (2) | 0.84 (1) | 0.32 (1) |
| 04 Readability | 3.69 (8) | 1.46 (2) | 8.89 (62) | 10.97 (13) | 1.58 (5) |
| 05 Error handling | 1.38 (3) | 0 (0) | 0.14 (1) | 0 (0) | 0 (0) |
| 06 Security | 1.84 (4) | 7.29 (10) | 2.29 (16) | 6.75 (8) | 7.56 (24) |
| 07 Performance (excessive I/O) | 0 (0) | 0 (0) | 0.72 (5) | 10.13 (12) | 0 (0) |
| 08 Concurrency and dependencies | 0.92 (2) | 2.19 (3) | 0.43 (3) | 0.84 (1) | 0.63 (2) |
| 09 Formatting: lines off the app's own style | 8.2% (163) | 3.6% (56) | 9.1% (720) | 1.3% (17) | 4.6% (152) |
| 10 Naming | 0 (0) | 0 (0) | 0.29 (2) | 0 (0) | 0.32 (1) |

my-first-app's high overall rate is twelve `await`s inside loops, all in `src/refresh/`, the code that fetches pages,
which may fetch one page at a time on purpose. SecureFit's is readability: ESLint counts 28 functions above its complexity limit and 11 over its
length limit. family-hub's is almost all security findings; it has the fewest lint issues for its size. These are
stand-ins measured on AI-built apps only. With no human-written baseline, they cannot reproduce the source report's
comparison of AI-written with human-written code.

## family-hub as built

family-hub was the only app built with `sv` in the loop, so it was also scanned three ways on 3 October, outside the
pipeline, to separate the effect of a newer `sv` from the effect of the owner's own answers. (These variants are not
the arms A, B, and C of the 20 September comparison in `METHODOLOGY.md`.)

| | A: `sv` 982f97e, blank template | B: `sv` 45b6d71, blank template | C: `sv` 45b6d71, the owner's manifest |
|---|---|---|---|
| Findings in the app | 220 | 220 | 202 |
| … own code / tests / vendored / dependencies | 24 / 52 / 142 / 2 | 24 / 52 / 142 / 2 | 14 / 44 / 142 / 2 |
| Own code by severity | 0 / 9 / 6 / 9 | 0 / 9 / 6 / 9 | 0 / 1 / 4 / 9 |
| Own-code findings per 1,000 lines | 7.56 | 7.56 | 4.41 |
| … critical or high | 2.84 | 2.84 | 0.32 |
| Set aside by the owner's reviews | — | — | 18 |
| Reviews that matched no finding | — | — | 7 |
| Requirements that apply | 217 | 217 | 223 |
| … not verified | 188 | 188 | 169 |
| … ruled out by the manifest | 1 | 1 | 216 |
| … stated or checked by hand by the owner | 0 | 0 | 26 (11 + 15) |
| Could not be placed | 236 | 236 | 15 |
| Threats: found / not verified / cannot place | 3 / 11 / 28 | 3 / 11 / 28 | 3 / 13 / 2 |
| Finding in the study's manifest | 1 | 0 | — |

- **A to B, a newer `sv` alone, changed nothing about the app.** `sv` 45b6d71 is 298 commits after 982f97e (`git
  rev-list --count 982f97e..45b6d71`). It found the same 220 findings, with the same fingerprints, and the same
  requirements and threats. The only difference is that the newer `sv` no longer flags its own template (item 3).
- **B to C, the owner's answers and reviews, changed what `sv` could decide.** The manifest ruled 216 requirements
  out and left 15 undecided instead of 236. The 18 reviews, all signed "owner", set aside ten own-code findings
  (seven of the eight SQL findings, the credential-like value, a file path, and a redirect) and eight in tests (three
  SQL, three file paths, two credential-like values). One high finding remains, the SQL at
  `familyhub/views/reminders.py:50`, which has no review.
- **The seven reviews that matched nothing** all name `tests.name-does-not-match-requirement`. That check reads the
  app's own tests and runs only when `sv` starts the app (`--run`); the owner's own run did, the as-built run did
  not. `sv` reported each as "no finding matches it any more", the same words it uses for a finding that is gone,
  which is deep-review finding R3 (`REVIEW.md`).

Under a method that treats every app alike, family-hub has the most high findings in its own code. As built, with
its owner's answers, it has one, and the fewest undecided requirements of any run in the study. A fair comparison of
apps built with and without `sv` needs both views.

## The ten `sv` issues the study raised, all fixed on `main`

The study's write-ups (`docs/sv-issues-2026-09-29.md`, `docs/sv-issues-2026-10-03.md` in the comparison repository)
and the Word report's appendix list ten issues. Seven came from the study itself; three (1, 2, and 7) the same
session found on 28 and 29 September, running `sv` over cato-pipeline's own code. Item 7 is two faults with two
fixes. Every fix is on `main` at the cut-off; each was merged before `eff3f17`, the commit the deep review read.

| # | Issue | Fixed by | Merged (Eastern) | In the study's `sv`? |
|---|---|---|---|---|
| 1 | Advisories with `last_affected` read as never ending (a false alarm on paramiko) | PR #423, `d463721` | 29 Sep 11:56 | yes, 982f97e has it |
| 2 | A shell variable reference (`"$OTHER_VAR"`) reported as a hard-coded credential | PR #433, `5fcde8b` | 29 Sep 17:17 | no |
| 3 | `sv`'s blank template trips its own credential check (`{new_password}`) | PR #443, `5a6c5ad` | 29 Sep 18:51 | no (45b6d71 has it) |
| 4 | A folder given with a trailing `/.` leaves Bandit's paths absolute and changes their fingerprints | PR #443, `5a6c5ad` | 29 Sep 18:51 | no |
| 5 | A missing tool reported as "installed and would not start" under amd64 emulation | PR #443, `5a6c5ad` | 29 Sep 18:51 | no |
| 6 | Scanning a subfolder of a git repository reports "not a git repository" (affected SecureFit) | PR #443, `5a6c5ad` | 29 Sep 18:51 | no |
| 7 | The download-piped-to-shell rule flagged a download read as data; files over 2 MB blocked the credential scan | PR #414, `3fc9324`; PR #407, `3231e6b` | 28 Sep 22:56; 28 Sep 19:31 | yes |
| 8 | A fully hash-pinned `requirements.txt`, and a `pylock.toml`, not read as lockfiles (affected family-hub) | PR #537, `7090598` | 3 Oct 20:55 | no |
| 9 | Python pre-release versions (`2.0.0rc1`) could not be compared (affected family-hub's werkzeug) | PR #535, `5da838e` | 3 Oct 20:43 | no |
| 10 | A report did not say which `sv` made it; the published image's `sv --version` said "commit unknown" | PR #538, `45d4917` | 3 Oct 21:05 | no |

Items 1 and 7 were fixed before the study began, so they did not affect its results. Items 2 to 6 were fixed on 29
September, the day they were raised; items 8 to 10 the evening of 3 October, the day they were raised. The study's
results were produced with `sv` 982f97e (and 45b6d71 for variants B and C), so items 3 to 6 and 8 to 10 are visible
in them (item 4 only in runs 2 and 3, item 5 as Semgrep and CodeQL "installed and would not start"). A re-run on
`main` would differ for family-hub's dependency figures at least.

## Where this document differs from the Word report

Recomputing turned up five places where the report is wrong. The numbers above are the right ones.

1. **Advisory snapshot.** The report says every run used `osv-pypi@sha256:9e6b684e…` and `osv-npm@sha256:4fde1d89…`
   (29 September). That is true of runs 2 to 10. Run 11, the one every figure comes from, recorded
   `osv-pypi@sha256:d94681b6…` and `osv-npm@sha256:3b324562…` in its `osv-snapshot.txt`. Its findings agree with run
   10's for all five apps, so no figure changes, but the provenance does. Which snapshot the as-built run used is
   not recorded in its folder.
2. **Commits between the two `sv` versions.** The report says 45b6d71 is 312 commits after 982f97e. Git counts 298.
3. **Why seven reviews matched nothing.** The report says they name a rule 45b6d71 does not have, so the owner must
   have used a newer build. 45b6d71 has that rule (`crates/sv-check/src/suite.rs`); it runs only with `--run`, which
   the as-built run did not pass. What the report infers about the owner's build does not follow.
4. **Test findings in variant C.** The report says the 52 findings in tests did not change. They went from 52 to 44:
   the owner's reviews set aside eight of them.
5. **family-hub's rate as built.** The report calls 0.32 critical or high findings per 1,000 lines "the lowest but
   one". Of the five apps, only the Fitness Tracker (0.92) is higher; it is the second highest.

The report's threat counts leave out "checked in part" (one each for the Fitness Tracker and the health tracker, two
for my-first-app), so its rows do not add up to each app's 42 or 40 threats. They are included above.

## Limits

- **No human baseline.** All five apps were built with AI tools. The study can describe them; it cannot say whether
  AI-written code is better or worse than people's, and its AI-code categories are stand-ins for the source report's
  measures.
- **One commit per app.** Each app is a single snapshot. Three of the five have one commit in their history, so how
  the code got that way cannot be read from it.
- **A blank manifest.** The same for every app, which is what makes them comparable, but it discards what the owners
  stated. It matters most for family-hub, as the as-built comparison shows. The template's defaults (customers,
  internet) are answers, not blanks.
- **Static only.** No app was started, so nothing about a running app was checked, and most of A01, A06, and A09 of
  the Top 10 is out of reach.
- **Uneven coverage.** Bandit reads Python only, so three apps got a second checker and SecureFit and my-first-app
  did not. Semgrep and CodeQL were not in the image. SecureFit's committed-secrets check did not run (item 6).
- **Few reviews.** Only family-hub's owner reviewed findings, and only in variant C. Several own-code findings in
  the other apps look like false alarms and have not been reviewed by a person.
- **Five apps.** Enough for a description, not for statistics.
- **The deep review.** The review of `sv` on 4 October found faults that could make some "checked" figures above
  optimistic (`REVIEW.md`). Whether any affected these five apps has not been re-checked.

## Sources

The comparison repository and its results, in `~/code/sv-study/`: `comparison/` (the pipeline, `apps.txt`,
`compare.py`, `same.py`, the mappings in `data/`, and the two issue write-ups in `docs/`), `results/run-2` to
`results/run-11`, and `results/as-built-2026-10-03/` (`latest-blank` is variant B, `latest-own` is variant C).
The Word report and its Markdown source. The fixes: `git log 157ddc3` and the pull request record
(`prs.json`, fetched 4 October 11:39). The `source` column of `study.csv` names the file behind each number, relative
to `~/code/sv-study/`.
