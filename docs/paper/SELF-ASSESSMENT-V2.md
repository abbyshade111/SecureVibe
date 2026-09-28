# `sv` checking itself: the v2 self-assessment

On 27 September 2026 `sv` was run against its own repository, the way it runs against any app, and every finding was
triaged by hand. It is the counterpart of v1's self-assessment of 20 September (`artifacts/self-assessment/` at tag
`v1-final`). The two are compared at the end. The results are also added to `TOP10.md` and `AGENTIC.md`. The figure
`figure-self-assessment.html` sets the two self-checks side by side.

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

**No real vulnerability was found.**

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

| | v1, 20 September | `sv`, 27 September (product code) |
|---|---|---|
| Findings | 195 | 252 |
| Critical / high / medium / low / info | 4 / 113 / 45 / 30 / 3 | 0 / 39 / 213 / 0 / 0 |
| False alarms | 160 (82%) | 191 (76%) |
| Accepted, by design | 21 | 61 |
| Left open | 14 | 0 |
| Real vulnerabilities | 2 (links drawn from data, fixed that evening in `9dc8140`) | 0 |
| Largest source of false alarms | rules that assume an app built from v1's own template (90 of the 95 under A01) | test code inside `sv`'s own source files (189) |
| What the whole repository adds | not run on v1's tests separately | 547 findings from tests, fixtures, examples, and scripts, and 19 manifest answers overruled by fixture code |
| Known-vulnerable dependencies | none recorded; 3 open install-script findings | none of 68 packages |
| Requirements | level 2; 161 apply: 31 passed, 95 attested, 12 partial, 20 failed, 3 not verified | level 1; 99 apply: 7 checked, 5 need attention (all traced to false alarms or accepted findings), 87 not verified; `sv` never says "passed" |
| Strong evidence | yes: it ran SecureVibe's own tests and probed it while running | none: `sv` is not a web app, so nothing ran, and its tests do not name requirements |

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

These are recorded as possible backlog items, not done here.

1. **Let a manifest name folders that are test fixtures or examples.** They would still be read, but they would not
   overrule the manifest, and their findings would be listed apart, the way the reports already list findings for
   requirements the app is not assessed against.
2. **Report findings inside Rust `#[cfg(test)]` modules, and test files in any language, apart from the product's.**
3. **A manifest field for "this is an MCP server"**, so the requirements about serving tools to a model can be asked
   of `sv` and of any app that serves them.
