# This is v1, archived

This branch holds SecureVibe **v1**: the local app that turns plain-language answers into a hardened web app
(Node, Express, EJS, `node:sqlite`) and checks it against OWASP ASVS 5.0, AISVS 1.0 and Secure by Design. It was
the top of the repository until 26 September 2026, when `sv` (the language-agnostic variant, in `agnostic/` until
then) became what `main` is. v1 is kept, not deleted.

**What is preserved exactly, for the paper.** History was never rewritten, so every commit hash the paper cites
still resolves.

- Tag `v1-paper` (`7fa07d6`): the commit that was `main` when the repository went public. It has a GitHub
  Release and a Zenodo version DOI, **10.5281/zenodo.22984709** (record https://zenodo.org/records/22984709), made
  from the release `v1-paper-doi` on the same commit. Cite that version DOI. The concept DOI (ending 708) always
  follows the repository's latest release, which is now `sv`'s.
- Tag `v1-final`: the last commit before the move. This branch (`v1`) starts there; the only commit on top of it
  is this file.

**What is in this tree.** Everything v1 needs to run and everything that guards it: `server/`, `shared/`,
`web/`, `templates/` (the app template every build starts from, with its own security test suite), `evals/` (the
five golden apps and their baselines), `self-assessment/` and `artifacts/self-assessment/` (v1 checking itself,
one snapshot from 20 September 2026), `data/` (the OWASP data and the knowledge files), `docs/` (including
`docs/paper/`) and the root npm files. `CLAUDE.md` and `README.md` here describe v1 as it was.

## Running v1 from this branch

1. **Node 26 and `npm ci`** at the root (the packages are an npm workspace).
2. **A real copy of the template's dependencies, not a symlink.** Copy an installed
   `templates/secure-web-app/node_modules` (about 57 MB) into place. With a symlink, every golden app fails the
   same way and still reports "succeeded".
3. **Your data is not in git.** `workspace/` (projects, `settings.json`, `llm-audit.jsonl`) and the root `.env`
   (API keys) are ignored by git, so they are on your machine only. To use existing projects from a fresh
   checkout, start v1 with `SECUREVIBE_HOME=<path to your old workspace>` and copy your `.env` into the root of
   the checkout. Never run `git clean -x` in a checkout that holds them.
4. `npm start` builds the web interface on first run and prints a one-time link on `127.0.0.1`.

## What to expect from the tests

- Tests that start a server or an app need to bind ports; inside a sandbox that blocks it they fail with
  `listen EPERM`. Run them in a normal terminal.
- **Nine server tests fail in a fresh worktree, and on the last `main` commit before the move as well**: three in
  `dast-harness`, one in `deps` (the CycloneDX tool), three in `config` and two in `secrets`. The fixtures
  they read depend on files git does not carry. They are not regressions; do not spend an hour on them.
- The evaluation harness (`npm run eval`, `--only <app>` for one app) builds the golden apps without AI and needs
  the real template `node_modules` from step 2.
- `npm run self-assess -- --no-ai` is free; without `--no-ai` it spends AI credit.

## Patching v1

A patch to v1 (including to the template) is made on this branch, where the evaluation harness is. `data/` here is
its own copy: `main` keeps changing its `data/` for `sv`, and the two will drift, which is expected.

Open v1 work is parked, not lost: `docs/BACKLOG.md` here lists it, and seven unmerged v1-era branches stay on
GitHub as they were (`claude/attention-recipe`, `claude/authz-role-names`, `claude/ci-hang`,
`claude/generated-code-escaping`, `claude/query-recipe`, `claude/report-table-escaping`, `claude/rust-ci`).
Rebase one onto this branch to revisit it.
