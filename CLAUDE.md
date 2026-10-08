# SecureVibe — notes for Claude Code sessions

SecureVibe (`sv`) is a Rust command-line tool and MCP server that checks an app written in any language against OWASP
ASVS 5.0, AISVS 1.0 and the Secure by Design checklist, and writes reports that say plainly what was verified and what
was not. The person builds the app in their own AI coding tool; `sv` picks up the code and grades it. `docs/DESIGN.md`
is the design, `docs/BACKLOG.md` is what is still to do, `docs/COVERAGE.md` counts what any check can speak to.

**v1 is archived, not part of this tree.** SecureVibe v1 (the app that asked questions and wrote a Node app) lived at the top
of this repository until 26 September 2026. It is on the `v1` branch (read `ARCHIVED.md` there) and at the tags `v1-paper`
and `v1-final`; its Zenodo version DOI, 10.5281/zenodo.22984709, is the one the paper cites. **History is never
rewritten** — no `filter-repo`, no squashing old commits, no force-push to `main` — because the paper, both USB bundles and
many documents cite commit hashes. A patch to v1 is made on the `v1` branch, never here. `docs/paper/` stays here.

## Layout

- `crates/` — the Rust workspace: `sv-frameworks` (the standards and which requirements apply), `sv-manifest`,
  `sv-scan` (reads the app's files, package manifests and lockfiles, and answers which technologies it uses), `sv-run`
  (starts the app behind the network fence, and the install step before it), `sv-check` (the checks: secrets,
  configuration, the tree-sitter rules, the probes, the outside tools' adapters), `sv-report` (the reports), `sv-cli`
  (the `sv` binary and its MCP server).
- `data/` — the OWASP frameworks (`data/frameworks`), the knowledge files (`data/knowledge`) and `sv`'s own JSON beside
  them. `data/README.md` says what each file is and what reads it; add a line there with any new file.
  Every run-time read goes through `sv_frameworks::data` (ADR-036): `SV_DATA_DIR` (the whole folder), then beside
  the program, then the folder it was compiled in (`env!("CARGO_MANIFEST_DIR")` plus `../../data`), which the Docker
  image keeps at the same path. A test fails on `CARGO_MANIFEST_DIR` anywhere else outside a test module.
- `docs/` — `ARCHITECTURE.md` (the ten-minute map: read it first), design, backlog, coverage, getting started,
  threat modeling, and `docs/paper/`.
- `tools/` — Python scripts (`coverage.py`, `pwned_passwords.py`, `semgrep_packs.py`, `semgrep_rule_map.py`, `codeql_suites.py`,
  `atlas_references.py`, `image_smoke.py`, `prompt_trial.py`, `adr_check.py`, `cvss4_tables.py`,
  `docs_page.py`) and one shell script,
  `install.sh`, which installs `sv` with its data outside the build folder; each with its purpose at the top. `examples/` — sample apps. `Dockerfile` — the container image.

## Commands

- Formatting, lints and tests, as CI runs them (`.github/workflows/rust.yml`):
  `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`.
- `docs/COVERAGE.md`, `docs/REQUIREMENTS.md` and `data/reach.json` are generated: after changing a rule, an adapter
  map or a hard-coded citation, run `python3 tools/coverage.py`, which rewrites all three; a test fails while any is out
  of date.
- CI also runs the tests with `SV_CREDIT_LOG` set, then `python3 tools/coverage.py --credits <that file>`, which fails
  when a check credits that is listed as only ever a finding, or never credits and is not listed.
- `tools/pwned_passwords.py` has no test and needs the network: run it outside the Claude Code sandbox, whose proxy cuts
  the reads short.
- Tests that start the app under test need a container backend (Docker or Colima); without one they assert the
  honest-absence path and say which branch they took. In CI, `SV_REQUIRE_BACKEND=1` makes a missing backend a failure.
- Rust builds inside the Claude Code sandbox cannot write `~/.cargo`; the error names a cache path and is misleading.
  Set `CARGO_HOME` and `CARGO_TARGET_DIR` to folders under the sandbox's temporary folder, or run cargo in the user's
  Terminal panel.

## Rules that hold everywhere

- **Evidence is honest.** Something not assessed is never a pass and never a failure, and a check that could not run says
  so in the report. Do not make a check look stronger than it is; automating a manual check means producing real evidence
  for it, never lowering the bar for what counts as verified.
- **Break your own rule and watch what catches it.** A new check is not known to work because it passes; it is known to
  work when the thing it guards is broken and it fails. Disable the guard, run the tests, read which ones go red, put it
  back. Count what caught it: one test failing where you expected several means the coverage is accidental, so add the fixture
  that makes it deliberate. A check that runs against one set of inputs checks a fraction of what can be written. A test
  whose setup can fail quietly is worse than no test: assert the setup worked, and that the thing you are looking for is
  really findable, before asserting it is not leaked.
- **Never print, log, echo, or commit a key**, the owner's or anyone's: not in a report, a test's output, a commit, or a
  message. `sv`'s secrets scan shows the first four characters and the length (`Secret::redact`), never the key; keep it
  that way. Test data that must look like a key is built from pieces at run time (see `.github/workflows/codeql.yml`), so
  the file holds none and GitHub's push protection has nothing to refuse.
- `sv` opens no network connection of its own, with one deliberate exception: `sv probe <address>` makes at most four
  read-only requests through `curl` to the address the owner types (five when the owner adds `--api <path>`), and one DNS query to this computer's resolver
  (`crates/sv-check/src/production.rs`, `live_tls.rs`). It asks only a public address, looked up once and held to
  (ADR-027). Advisory data is something the user downloads and points it at. A second exception, only when the owner
  sets `install = true`: `sv run` starts a container, given only the app's dependency files and made from one of
  Docker's own `python` or `node` images and no other, that downloads its packages from PyPI or npm without running
  any of their code (ADR-052); the app itself stays fenced. Keep it that way.
- A citation is a claim: cite a requirement only when the check really speaks to it.

## Working style the owner expects

- Plain language in reports and documents: the owner is not a programmer. No jargon without an explanation.
- One spelling standard: American English (color, behavior, organization, recognize) with the Oxford comma, in
  everything a person reads. Identifiers and JSON keys keep their names.
- Say what was verified and what was not. Report test results as they are.
- One app is anonymous in everything public, the paper included: the health-tracking app the owner built for a friend.
  Call it "a health-tracking app built for a friend" in prose and "Health tracker" in a table or figure, and never write
  its real name in a committed file, a figure, or anything else that leaves this machine. Its subject is somebody's
  health and a public repository is permanent. The name is deliberately not recorded here, so this file cannot leak it.
  Anonymized before the repository went public (20 September 2026, `d5d5719`); the owner confirmed on 4 October 2026
  that the paper follows suit, after the comparison study had put the name back into `docs/paper` that morning.
- Git is pre-approved. Commit and push to a working branch, open pull requests, and merge one into `main` once its checks
  are green, without asking first. Say what went in afterwards; a short, honest account of each change is the point, not a
  request for permission. The owner asked for this on 18 September 2026.
- Still ask first, every time: anything that spends the owner's money, anything that changes the repository's settings or
  visibility, rewriting or force-pushing history, and deleting anything. Those are the owner's money or are hard to undo, and
  the pre-approval above does not reach them.
- **A decision's record goes in the same pull request as the decision.** A decision is anything that changes what
  counts as evidence or at which tier, what `sv` runs or connects to, what it writes into someone's folder, the network
  fence, a dependency, or a default that changes what a report concludes, and every choice the owner makes when asked.
  Its record is a new ADR in `docs/adr/` or a dated "Later" entry on an existing one, with its **Governs:** list kept
  true. For anything substantial, write the record first, as `Status: proposed` in the backlog claim, and make it
  accepted in the pull request that builds it. A pull request that touches a governed file and does not change its
  record says why on a line `ADR-0NN: unchanged, because ...`; the "Decision records" check fails without it. Until
  4 October 2026 every one of `sv`'s records was written one to seven days after the decision, and only when a review
  noticed. **The owner made "Decision records" a required check on `main` on 4 October 2026**: a pull request does not
  merge until it passes, so add the line, or change the record, before asking for the merge. A pull request opened
  before 21:55 that day ran the check under its old name, `check`, and waits for "Decision records" until it is
  pushed to again or its description is edited.
- Claim a backlog item in `docs/BACKLOG.md` before starting it, and commit that claim on its own. Saying so in a message
  to another session does not count: a session that is not running never receives it, and one that is will not see it again
  after its context is summarized. On 20 September 2026 two sessions each read the backlog, each correctly saw an item
  unclaimed, and both built it.
  Append the claim at the end of the "Next" section, never at its top, and merge the claim's pull request before building
  on it: on 8 October 2026 every session inserted at the top, so a branch an hour old conflicted with `main` there, and the
  same conflict was resolved three times at a 20-minute CI round each. For the same reason a new test goes in a sibling
  test file (`src/<module>/tests.rs`, or one of its own) rather than at the end of a module's `mod tests`, and a new DESIGN
  section is a section of its own rather than a paragraph on an existing one.
- Before deleting a branch, compare its files with `main` (`git diff --stat main..<branch>`); never decide from
  `git branch --merged` alone. A commit that reached `main` by cherry-pick or rebase arrives with a different identity, so git
  calls the branch unmerged while every line of it is already there.
- **Keep the disk tidy, and look before a long run.** Run `df -h ~` before a paid trial, an evaluation, or a fresh
  `cargo` target folder. The Mac's disk is the owner's and nearly full of their own work: on 7 October 2026 it reached
  152 MB free in the middle of a 110-build trial, and a `cargo test` then printed no failures because nothing compiled at
  all (count the `test result` lines, not only the failures). Reuse one target folder rather than making one per branch;
  each is 1 to 7 GB. When your work is finished, list what you made that can go: build folders, scratch worktrees,
  trial apps already scored and written up, logs. Then ask the owner before deleting any of it, saying what each is,
  its size, and whether it can be made again. Deleting still needs the owner's yes, every time; listing it does not.
- Never edit a user's own data or an app someone gave you to check by hand, except to repair data, and say so.
