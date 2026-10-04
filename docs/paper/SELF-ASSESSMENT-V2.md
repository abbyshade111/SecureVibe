# `sv` checking itself: the v2 self-assessment

On 27 September 2026 `sv` was run against its own repository, the way it runs against any app, and every finding was
triaged by hand. It is the counterpart of v1's self-assessment of 20 September (`artifacts/self-assessment/` at tag
`v1-final`). The two are compared near the end. On 4 October the same check was repeated on `sv` as it stood at this
document's cut-off, `main` at `157ddc3` (4 October 2026, 11:37 Eastern); the last section compares the two dates. The
results are also added to `TOP10.md` and `AGENTIC.md`. The figure `figure-self-assessment.html` sets the three
self-checks side by side: v1, `sv` on 27 September, and `sv` on 4 October.

## How it was run

- **Code.** Commit `7e533da`, with `securevibe.toml` as committed in `306faec`.
- **The manifest.** `securevibe.toml` at the repository root says what `sv` is: a local command-line tool with an MCP
  server over standard input and output, with no sign-in, no network port, no data about people, and no AI feature of
  its own. It was written from `sv`'s code by an AI coding session and committed at the owner's choice so anyone can
  re-run this. Every answer in it is the AI tool's statement, and the file says so.
- **The command.** `sv report <folder> --tools --advisories <osv>`. Without `--run`: `sv` is not a web app, so there
  is nothing to start and send requests to, and every check that needs a running app is reported as not assessed.
- **Outside tools that ran:** semgrep 1.176.0 and bandit 1.9.4. CodeQL is not installed, and gosec and Brakeman
  apply only to test fixtures; the reports say so.
- **Known vulnerabilities:** OSV's Rust advisory export, downloaded that morning (2,856 records, updated
  26 September).
- **A sandbox note.** The first run was made inside the AI session's sandbox, and there semgrep "would not start"
  (`ca-certs: empty trust anchors`), because the sandbox hides the system's certificates. `sv` reported that as a
  gap rather than a clean result. Both runs below were made outside the sandbox, where semgrep ran.

Two runs, because of what the first one showed:

1. **The repository as it is** (`self-assessment-v2/repository/`). This is what anyone gets from `sv report .`.
2. **The product code only** (`self-assessment-v2/product-only/`). A copy without `crates/*/tests/`, `examples/`,
   `tools/`, and `docs/`; `files-checked.txt` lists the 105 files it kept. It is `sv`'s source, its container
   scripts, its data, the Dockerfile, and CI.

## What the repository run showed first: `sv` cannot tell its test fixtures from its code

`sv`'s tests include deliberately vulnerable fixture apps and example apps: a Flask app with `authlib` and `pyjwt`, a
Stripe checkout, a Go app with raw SQL, a Rails app with no CSRF protection, and more. `sv` read them as part of the
app. Its corroborators, which may only ever add capabilities, overruled the manifest 19 times ("securevibe.toml says
auth is not used, but `authlib` is declared in examples/flask-booking/requirements.txt") and switched on requirements
that do not apply to `sv`.

The repository run found **804 findings** (3 critical, 126 high, 648 medium, 27 low):

| Where | Findings |
|---|---|
| Test files (`crates/*/tests/`) | 396 |
| Fixture apps inside the tests | 113 |
| Maintenance scripts (`tools/`) | 28 |
| Example apps (`examples/`) | 10 |
| Product code | 257 |

It marked 17 requirements as needing attention. 12 of them come only from the tests, fixtures, examples, and scripts; the other 5 are the same ones the product-only run marks.

**Nothing in the tests, fixtures, examples, or scripts is a vulnerability in `sv`.** The fixtures and examples are
meant to be vulnerable: they are what `sv`'s own tests check that it catches. The 28 script findings are
subprocess calls, fixed `https://` fetches with timeouts, and SHA-1 used because the Pwned Passwords range API
requires it. This is the same fault v1's self-check had, one level up. v1's rules assumed an app built from v1's own
template; `sv` assumes every file in the folder is the app.

## The product code

**252 findings**: 39 high and 213 medium. Each is in `product-only/triage.json` with its verdict and reason.

| Rule | Findings | Verdict | Why |
|---|---|---|---|
| A file path built from a value | 212 | 159 false alarms, 53 accepted | The 159 are test code inside source files (`#[cfg(test)]` modules). The 53 are `sv` reading files inside the app it was pointed at, which is its job. Paths from outside come only through the MCP server, which canonicalizes them, keeps them under `--root`, and refuses symlinks; none of the 212 is in that code outside its tests |
| A plain-text WebSocket address (semgrep) | 18 | false alarms | 17 in the test cases of `sv`'s own `ws://` rule, 1 in that rule's documentation |
| A credential written in the code | 16 | 13 false alarms, 3 accepted | 12 are test passwords in test modules, and 1 is a `{new_password}` placeholder in the manifest template. The 3 are passwords `sv` deliberately sends to the app under test: a wrong one and a long one |
| A shell command built from a value | 4 | accepted | Each runs a fixed program (`docker`, or a tool from `data/adapters.json`) with its arguments as a list; no shell is involved |
| An insecure request (semgrep) | 1 | accepted | The browser driver reaching Chromium's control port on 127.0.0.1 inside the fenced container |
| A disallowed hash function | 1 | false alarm | SHA-1 in a test that checks the breached-password evidence; the Pwned Passwords range API requires SHA-1 |
| **Total** | **252** | **191 false alarms, 61 accepted, 0 open** | |

**No real vulnerability was found.** *(In hindsight, 4 of the 61 accepted were real: the deep review of 4 October showed
that the lines they flag write through a link, or read a planted file. The code of all 4 was unchanged on 4 October.
See the last section.)*

- **Test code inside source files is 75% of the findings (189 of 252).** Rust keeps unit tests in the same file as
  the code, and `sv` reads the whole file.
- **Known vulnerabilities:** all 68 packages in `sv`'s bill of materials were compared with the 2,856 Rust advisories,
  with no match and nothing it could not compare (`sv audit`).
- **Requirements.** 99 apply at ASVS level 1, given what the manifest says.
  - 5 are marked as needing attention: V1.2.5, V4.4.1, V5.3.2, V11.4.1, and SBD-AC-05. Each comes only from the
    findings above, which are all false alarms or accepted.
  - 7 were checked by an automated check: V1.2.4, V1.3.2, V11.3.1, V11.3.2, V15.2.1, and two CI-hardening
    requirements, AC.12.1 and AC.12.2. For the last two, no workflow runs fork code with secrets, and every checkout
    drops its credentials.
  - 87 were not verified by anything.
- **How it is built with AI (AISVS Appendix C).** Of the 19 requirements, 13 are handed to the AI coding tool as
  rules, 1 is left to the owner's decision (human review of AI-written code), and 5 are reached by nothing in `sv`
  (among them a written AI workflow, a threat model for every AI tool including MCP servers, and logging of prompts
  and responses).

## What this self-assessment cannot see

- **The running app.** `sv` is not a web app, so every probe and signed-in check is not assessed.
- **`sv` as an MCP server.** The manifest can say that an app reaches tools over MCP, but not that it *is* an MCP
  server that an AI tool drives. So the requirements about serving tools to a model are not asked of `sv`. That is the
  surface where `sv`'s one tool-misuse incident happened (the report writer following a symlink, #77). It is a gap in
  what `sv` can say about itself, recorded here rather than papered over.
- **CodeQL.** It was not installed, so its data-flow checks did not run on `sv`'s scripts. CI runs CodeQL on every
  change (`.github/workflows/codeql.yml`), and that is where `sv`'s real CodeQL findings came from (`TOP10.md`).
- **Design questions.** None are answered in the manifest, so the design-review requirements stay not verified.

## v1 and v2 checking themselves

| | v1, 20 September | `sv`, 27 September (product code) | `sv`, 4 October (product code) |
|---|---|---|---|
| Findings | 195 | 252 | 479 |
| Critical / high / medium / low / info | 4 / 113 / 45 / 30 / 3 | 0 / 39 / 213 / 0 / 0 | 0 / 27 / 448 / 4 / 0 |
| False alarms | 160 (82%) | 191 (76%) | 413 (86%) |
| Accepted, by design | 21 | 61 | 60 |
| Left open | 14 | 0 | 6 |
| Real vulnerabilities | 2 (links drawn from data, fixed that evening in `9dc8140`) | 0 found then; 4 in hindsight | 6, all already in the backlog from the deep review, none fixed at the cut-off |
| Largest source of false alarms | rules that assume an app built from v1's own template (90 of the 95 under A01) | test code inside `sv`'s own source files (189) | test code inside `sv`'s own source files (413), 404 of them now marked by `sv` and listed apart |
| What the whole repository adds | not run on v1's tests separately | 547 findings from tests, fixtures, examples, and scripts, and 19 manifest answers overruled by fixture code | 683 findings from tests, fixtures, examples, scripts, and the bill of materials, all listed apart but 1, and no manifest answer overruled by those folders |
| Known-vulnerable dependencies | none recorded; 3 open install-script findings | none of 68 packages | not checked: no advisory data was given |
| Requirements | level 2; 161 apply: 31 passed, 95 attested, 12 partial, 20 failed, 3 not verified | level 1; 99 apply: 7 checked, 5 need attention (all traced to false alarms or accepted findings), 87 not verified; `sv` never says "passed" | level 1; 110 apply: 6 checked, 4 need attention, 100 not verified |
| Strong evidence | yes: it ran SecureVibe's own tests and probed it while running | none: `sv` is not a web app, so nothing ran, and its tests do not name requirements | none, for the same reasons |

- **v1's open items.** 2 were the real ones, fixed that evening. 3 were install scripts allowed in dependencies, 1 a
  slow regular expression, and 7 missing documentation. The last was the 429 false alarm: a rate limiter answered
  before the route could (`9dc8140`).
- **Requirements.** v1's 31 passes rest on its own tests and on probes of SecureVibe running; v1's evidence model
  also counts medium evidence, such as configuration checks. `sv`'s "checked" means an automated check looked and found
  nothing wrong on part of a requirement. It is never a pass, so the two rows are not the same measure. v1's
  assessment is from `artifacts/self-assessment/compliance-report.json` at `v1-final`.

**What the comparison says:**

- **Both self-checks were mostly noise, from the same cause.** Each version's rules made an assumption about what
  they were reading that did not hold for the tool itself. v1 assumed an app built from its own template, and `sv`
  assumes every file in the folder is the product. In both, a person had to read every finding. Neither check could
  have been trusted without that.
- **v2's product code came out cleaner.** Nothing open, nothing real, and no known-vulnerable dependency, against
  v1's two real findings fixed that evening. `sv` is also the smaller program: it is not a web app, holds no data,
  and has no sign-in.
- **What each could prove depends on what each is.** v1 is a web app, so its self-check could run its tests and
  probe it running, and 31 requirements passed on that evidence. `sv` is a command-line tool: its self-check ran
  nothing, so it can find faults but cannot show that any requirement holds. The next step for `sv` would be tests
  that name the requirements they prove, which is what `sv` asks of every other app.

## Three things `sv` could do about this

These are recorded as possible backlog items, not done here. *(All three were built that same evening, Eastern time:
test code listed apart, including Rust's test modules (#316); a manifest field for an MCP server (#318); and folders
named as not the app (#327). The last section shows what each changed.)*

1. **Let a manifest name folders that are test fixtures or examples.** They would still be read, but they would not
   overrule the manifest, and their findings would be listed apart, the way the reports already list findings for
   requirements the app is not assessed against.
2. **Report findings inside Rust `#[cfg(test)]` modules, and test files in any language, apart from the product's.**
3. **A manifest field for "this is an MCP server"**, so the requirements about serving tools to a model can be asked
   of `sv` and of any app that serves them.

## 4 October: the same check on current `sv`

On 4 October the check was repeated on `sv` as it stood at the cut-off, and every product finding was triaged again.
The reports are in `self-assessment-v2/2026-10-04/`, laid out as the 27 September ones are (`repository/`,
`product-only/`, and, in `product-only/`, `files-checked.txt` and `triage.json`). The 27 September files are
unchanged.

### How it was run

- **The scanner.** The published container image `ghcr.io/abbyshade111/securevibe-sv`, tagged with commit `84dcbd4`
  (fingerprint `sha256:c59678b3…`), so the scanner is `sv` at `84dcbd4`. `84dcbd4` was merged at 11:19 Eastern, and
  the image was built from it at 11:32. The only commits between it and the cut-off change `docs/BACKLOG.md`, so the
  scanner is the same code as the source it scanned.
- **The source scanned.** `main` at `157ddc3`, exported with `git archive` into a folder of its own, so it has no git
  history. The product-only copy was made the same way as on 27 September: every file except `crates/*/tests/`,
  `examples/`, `tools/`, and `docs/`. It has 143 files, against 105.
- **The command.** `sv report /app --tools --out /out` inside the image, with `--network none`, for each copy. The
  only network use was downloading the image.
- **Three differences from 27 September, each a gap the reports name:**
  - **semgrep did not run.** The image does not include it, and the reports say so. On 27 September it gave 19 of
    the product run's 252 findings (18 false alarms and 1 accepted). The comparisons below say where that matters.
    bandit is not in the image either, but it would not have run: the only Python in the repository is in folders
    named as not the app, and `sv` now picks outside tools by the languages of the app's own code. On 27 September it
    found nothing in the product code.
  - **No known-vulnerability check.** No Rust advisory export was on this computer, and none was downloaded, so
    `--advisories` was left off. V15.2.1 (known-vulnerable dependencies) is therefore not checked this time; on
    27 September it was.
  - **No git history**, because the source was exported with `git archive`. The one check that reads history, whether
    a secrets file was ever committed, had nothing to read.
- **Triage.** A 27 September verdict was reused only where the rule, the file, and the text of the flagged line are
  all unchanged. 215 findings were unchanged; 212 kept their verdict, and 3 were given a new one, because the deep
  review of 4 October showed them real (below). The other 264 were read afresh. `triage.json` marks each reused
  verdict (`from_27_september`).

### The product code

**479 findings**: 27 high, 448 medium, and 4 low. Each is in `2026-10-04/product-only/triage.json` with its verdict
and reason.

| Rule | Findings | Verdict | Why |
|---|---|---|---|
| A file path built from a value | 443 | 387 false alarms, 50 accepted, 6 real | The 387 are test code. The 50 are `sv` reading files inside the app it was pointed at, its own data files and scratch files, and the MCP server serving a report under its guards. The 6 are below |
| A credential written in the code | 20 | 17 false alarms, 3 accepted | 13 are made-up values in test code, and 4 are made-up passwords in the fake app that `sv`'s sign-in tests drive. The 3 are the passwords `sv` deliberately sends to the app under test, the same as on 27 September |
| A shell command built from a value | 7 | accepted | 6 run a fixed program with its arguments as a list. 1 runs the app's own test command, as the owner wrote it in `securevibe.toml`, with a shell inside the app's own fenced container |
| A floating AI model name | 4 | false alarms | Test inputs for `sv`'s own rule |
| An MCP server started without a pinned version | 3 | false alarms | Test inputs for `sv`'s own rule |
| A sign-in token in the code | 1 | false alarm | A made-up, unsigned test token |
| A disallowed hash function | 1 | false alarm | SHA-1 in a test of the breached-password evidence, as on 27 September |
| **Total** | **479** | **413 false alarms, 60 accepted, 6 real** | |

**The six real findings.** None is new to the record: each is a weakness the deep review of 4 October
(`sv-review-2026-10-04.md`, at `eff3f17`) had already reproduced, and each was still open at the cut-off.

| Finding | Where | What is wrong | Review item |
|---|---|---|---|
| 1 | `sv-cli/src/main.rs`, `sv rules` writing `AGENTS.md` | Written with a plain write, which follows a link: if `AGENTS.md` is a link to a file elsewhere, that file is overwritten | S3 |
| 2 | `sv-cli/src/main.rs`, `sv notes` writing `security-notes.md` | The same, for the notes file. The MCP server refuses a link first; the command line does not | S3 |
| 3 | `sv-cli/src/main.rs`, `sv bundle` writing its zip | A link already at the zip's name, beside the app, has the file it points to overwritten | S4 |
| 4 | `sv-check/src/adapters.rs`, reading an outside tool's report | The report is a fixed name in the shared temporary folder, and whatever file is there is taken as the tool's report | S6 |
| 5, 6 | `sv-scan/src/files.rs`, reading a file of the app, whole or in pieces | A named pipe in the app is read like a file and waits forever, so `sv` hangs | S12 |

Findings 1 to 3 are what the rule describes: a file operation that goes somewhere other than the folder it meant
to use. Findings 4 to 6 are real weaknesses on the line the rule flagged, but not the one it names. Two cautions go
with them:

- **`sv` flagged these lines on 27 September too, and they were accepted.** Findings 1 to 4 were among the 61
  accepted on 27 September, with the code unchanged. That triage gave every "file path built from a value" finding
  outside test code the same reason (`sv` reads files in the app it was pointed at), and did not ask whether a write
  could follow a link. Read the same way now, 27 September had 4 real findings, not 0. Findings 5 and 6 are in code
  added that evening, after the run (#320). Whether 27 September's code had the same hang was not checked.
- **This triage was not independent of the review.** It was done with the review in hand, which is why these
  were caught; it did not find anything the review had not. Its accepted verdicts are only as good as that reading.

**What changed in `sv`'s output, and why.** The scanner's rule for file paths is the same as on 27 September
(`data/ast-rules.json` did not change for it), so almost all the difference comes from three things:

- **`sv` grew.** Its Rust source outside the test folders went from 56,384 lines to 88,137, mostly in test modules
  inside the source files. Findings in test code went from 189 (17 of them semgrep's) to 413. Findings outside test
  code went from 63 to 66: 60 accepted and 6 real, against 61 accepted and 2 false alarms (the template placeholder,
  since fixed, and a semgrep finding in a comment).
- **`sv` now tells its readers which findings are in test code.** Since #297 and #316 (27 September, after the
  first run, that evening), a finding inside a `#[cfg(test)]` module or a `#[test]` function is marked and listed after the app's
  own, in a section saying that test code can still hold a real key. 404 of the 413 false alarms are listed apart
  that way. The reader's first list has 75 findings: 60 accepted, 6 real, and 9 false alarms in test code `sv` did
  not recognize. 5 of those 9 are in test modules declared `#[cfg(all(test, unix))]` rather than `#[cfg(test)]`, and
  4 are in `fake_app.rs`, a whole file compiled only for tests by a line in another file. On 27 September all 252 were
  in one list.
- **semgrep did not run.** That removes 19 findings and the one requirement they alone touched (V4.4.1, a plain-text
  WebSocket address), which no longer needs attention. Leaving semgrep out of 27 September too, the same rules gave
  233 findings then, 173 of them false alarms (74%), against 479 and 413 (86%) now.

**The false-alarm share rose from 76% to 86%** because `sv`'s own tests grew faster than its other code. What a person
must read before reaching something real fell, though: 75 findings in the first list, against 252 in one list on
27 September.

**Requirements.** 110 apply at ASVS level 1, against 99.

- 11 more apply. 6 are about serving tools over MCP (AISVS C10), now asked of `sv` because the manifest says it is an
  MCP server (#318). That closes the gap the 27 September run recorded. The other 5 (C2.2.1, C2.2.2, C7.3.1, C8.1.1,
  and C8.2.1) are switched on because `sv`'s own code overruled three more manifest answers (below).
- 4 need attention: V1.2.5, V5.3.2, V11.4.1, and SBD-AC-05. V5.3.2 now carries the six real findings; the other three
  come only from accepted findings and false alarms.
- 6 were checked by an automated check: V1.2.4, V1.3.2, V11.3.1, V11.3.2, AC.12.1, and AC.12.2. V15.2.1 is not among
  them this time, because no advisory data was given.
- 100 were not verified by anything.
- AISVS Appendix C is unchanged: 13 handed to the AI coding tool as rules, 1 left to the owner, and 5 reached by
  nothing.

**`sv`'s own code still overrules its manifest.** In the product run, 13 manifest answers were overruled by what the
corroborators found, against 10 on 27 September. They are `sv`'s stand-ins and its own rule text, not features of
`sv`: the fake app its sign-in tests drive (`bcrypt`, `Multipart`), the sign-in and AI stand-ins it starts inside the
fence to test other apps (`oidc-provider.mjs`, `model-provider.mjs`), and words such as `embeddings` and `web_search`
in its own code. This is the 27 September run's fixture problem in a smaller form, inside the product code, where
naming folders as not the app cannot reach.

### The repository run

**1,162 findings** (3 critical, 98 high, 1,057 medium, and 4 low), against 804.

| Where | 27 September | 4 October |
|---|---|---|
| Test files (`crates/*/tests/`) | 396 | 645 |
| Fixture apps inside the tests | 113 | 26 |
| Maintenance scripts (`tools/`) | 28 | 10 |
| Example apps (`examples/`) | 10 | 1 |
| Product code | 257 | 479 |
| The bill of materials | — | 1 |
| **Total** | **804** | **1,162** |

- **Naming folders as not the app worked.** The committed `securevibe.toml` now names `crates/*/tests`, `examples`,
  `tools`, and `docs` as not the app (#327). Their findings are still counted, but listed apart, and what they use no
  longer changes which requirements apply. On 27 September the repository run overruled 19 manifest answers, 9 of
  them (among them `jwt`, `payments`, `mcp`, and `multi-tenant`) only because of those folders. Now it overrules the
  same 13 as the product run, and none comes from them. 1,086 of the 1,162 findings are listed apart as test or
  sample code.
- **The fall in fixture, script, and example findings is all outside tools.** semgrep and bandit gave 87 of the
  113 fixture findings, 24 of the 28 script findings, and all 10 example findings on 27 September. bandit's 46 there
  are gone because those folders are not the app, so `sv` no longer runs it for their Python. semgrep's 75 are gone
  because it was not installed; whether `sv` would still give it those folders was not tested. `sv`'s own rules found
  26 in the fixtures both times.
- **Requirements.** 8 need attention, against 17. 4 are the product run's; the other 4 (V1.2.4, V1.3.2, V11.3.1, and
  V11.3.2) come only from deliberately vulnerable fixture apps. Findings in test code still count toward their
  requirements, by design, so the repository run marks as needing attention requirements that the product run checked.
- **One fixture problem is left.** The bill of materials still reads the fixtures' lockfiles, and reports itself as
  incomplete because some of them are deliberately broken. That is the one finding from those folders in the reader's
  first list.

### What the two dates say together

- **The noise is now sorted, not removed.** Between the two runs `sv` gained the three changes the first run asked
  for, and each did what it was meant to: test code is listed apart, fixtures no longer overrule the manifest, and the
  MCP requirements are asked. The product run still has more findings, and a higher share of false alarms, because
  `sv`'s own tests grew by more than half.
- **The real findings were found by reading against the review, not by `sv` alone.** `sv` flagged the same lines on
  both dates. On 27 September a person accepted them; on 4 October, with the deep review in hand, a person did not.
  A self-check is only as good as the triage that reads it, and a reason applied to a whole rule at once is where this
  one went wrong.
- **What this run could not see** is the same as on 27 September, less the MCP gap, plus semgrep, the advisory
  check, and git history, each named in the reports.
