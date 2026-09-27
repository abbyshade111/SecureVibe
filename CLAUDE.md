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
  `sv-scan` (language-agnostic scanners: secrets, configuration, lockfiles, tree-sitter rules), `sv-run` (starts the app
  behind the network fence), `sv-check` (the checks), `sv-report` (the reports), `sv-cli` (the `sv` binary and its MCP server).
- `data/` — the OWASP frameworks (`data/frameworks`), the knowledge files (`data/knowledge`) and `sv`'s own JSON beside
  them. Crates find it through the folder they were compiled in (`env!("CARGO_MANIFEST_DIR")` plus `../../data`);
  `SV_DATA_DIR` overrides the OWASP part. The Docker image keeps `crates/` at the same path for that reason.
- `docs/` — design, backlog, coverage, getting started, threat modeling, and `docs/paper/`.
- `tools/` — Python scripts (`coverage.py`, `pwned_passwords.py`, `semgrep_packs.py`, `atlas_references.py`,
  `image_smoke.py`), each with its purpose at the top. `examples/` — sample apps. `Dockerfile` — the container image.

## Commands

- Formatting, lints and tests, as CI runs them (`.github/workflows/rust.yml`):
  `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --workspace`.
- `docs/COVERAGE.md` is generated: after changing a rule, an adapter map or a hard-coded citation, run
  `python3 tools/coverage.py`; a test fails while the document is out of date.
- `tools/pwned_passwords.py` has no test and needs the network: run it outside the Claude Code sandbox, whose proxy cuts
  the reads short.
- Tests that start the app under test need a container backend (Docker or Colima); without one they assert the
  honest-absence path and say which branch they took.
- Rust builds inside the Claude Code sandbox cannot write `~/.cargo`; the error names a cache path and is misleading.
  Run cargo in the user's Terminal panel.

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
- `sv` opens no network connection of its own; advisory data is something the user downloads and points it at. Keep it that way.
- A citation is a claim: cite a requirement only when the check really speaks to it.

## Working style the owner expects

- Plain language in reports and documents: the owner is not a programmer. No jargon without an explanation.
- One spelling standard: American English (color, behavior, organization, recognize) with the Oxford comma, in
  everything a person reads. Identifiers and JSON keys keep their names.
- Say what was verified and what was not. Report test results as they are.
- Git is pre-approved. Commit and push to a working branch, open pull requests, and merge one into `main` once its checks
  are green, without asking first. Say what went in afterwards; a short, honest account of each change is the point, not a
  request for permission. The owner asked for this on 18 September 2026.
- Still ask first, every time: anything that spends the owner's money, anything that changes the repository's settings or
  visibility, rewriting or force-pushing history, and deleting anything. Those are the owner's money or are hard to undo, and
  the pre-approval above does not reach them.
- Claim a backlog item in `docs/BACKLOG.md` before starting it, and commit that claim on its own. Saying so in a message
  to another session does not count: a session that is not running never receives it, and one that is will not see it again
  after its context is summarized. On 20 September 2026 two sessions each read the backlog, each correctly saw an item
  unclaimed, and both built it.
- Before deleting a branch, compare its files with `main` (`git diff --stat main..<branch>`); never decide from
  `git branch --merged` alone. A commit that reached `main` by cherry-pick or rebase arrives with a different identity, so git
  calls the branch unmerged while every line of it is already there.
- Never edit a user's own data or an app someone gave you to check by hand, except to repair data, and say so.
