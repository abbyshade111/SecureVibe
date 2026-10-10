# Promote `sv` to the top of the repository, and keep v1 for the paper

**Status:** done, 9 October 2026

**The owner's decision,
26 September 2026:** `sv` is the stronger product and becomes what `main` is; v1 is archived, not
lost, and its code stays preserved exactly for the paper. **When** is for the sessions to work out
together — this entry is the place. **[taken: the v1 builder, "Vibe-coding builder", 26 Sep 2026]**
The owner asked for the move to be claimed once every session was clear; see "The move is claimed", below.

**Where it stands (this pull request, 26 September 2026):** done are the copy of `workspace/` and `.env` to
`~/securevibe-v1-backup-2026-09-26` (verified identical), the tag `v1-final` at `412092d` with its Release, and the
`v1` branch with `ARCHIVED.md`. This pull request makes the move itself: v1's tree, its `docs/` other than
`docs/paper/` and its root npm files leave; `crates/`, `Cargo.*`, `Dockerfile`, `examples/`, `tools/`, the README and
`agnostic/docs/` move up; `agnostic/data/` merges into `data/` (no file name collides with `frameworks/` or
`knowledge/`), which is why the shared files are now reached by `../../data` from a crate like sv's own; the two
Python tools that set `ROOT = AGNOSTIC.parent` now use the repository root; the workflows, `.dockerignore` and
`.gitignore` follow. **Not done, and the owner's:** `~/code/my-first-app/.mcp.json` and the PATH line in `~/.zshrc`
(both point at `sv-tool/agnostic/target/release/sv`; updated, the owner said on 27 September 2026), the local image `securevibe/sv:local`, a Dependabot entry for
the Rust packages (there was none; added in #226), and turning the freeze off once this merges. **Not verified by me before
opening this pull request:** a local `cargo test`, which the permission check stopped; CI is the first full run.
(Run afterwards, 27 September 2026, by securevibe-e8 on `main` at `d6e781c`: 1,074 passed; the one failure,
`the_fence_really_blocks_outbound_traffic`, needs outbound network, which that sandbox has none of.) After
it merges, run `tools/pwned_passwords.py` once outside the sandbox (it has no test).
**All of the owner's part is done, the owner said on 27 September 2026:** `pwned_passwords.py` was run
after the move, the USB bundles are up to date, the community standards page shows every item done,
and the local image `securevibe/sv:local` is replaced by the published `ghcr.io/abbyshade111/securevibe-sv`.
Tag protection is on: a tag ruleset, "protect v1's tags", checked through GitHub's API the same day
by session securevibe-e2 (active, `refs/tags/v1-*`, deletion, update, and force-move all refused, no
bypass).
Text below that says `agnostic/…` was written before the move.

**Rules that hold whatever the plan:**
- **Never rewrite history.** No `filter-repo`, no squashing old commits, no force-push to `main`.
  The paper's appendix, both USB bundles, and the ADR cross-references cite commit hashes (see the
  message of `7fa07d6`), and a rewrite changes every one of them. Moving files in an ordinary commit
  keeps every hash.
- **`data/` stays where it is.** `sv` reads it — the OWASP frameworks, `data/knowledge`, and more —
  and so does v1. So does `docs/paper/`.
- **v1 stays reachable three ways:** a tag `v1-paper` at the commit that was `main` when the
  repository was made public (the owner's choice); a tag `v1-final` at the last commit before the
  move; and a `v1` branch for anybody who needs to patch it. Each tag gets a GitHub Release, a
  snapshot anybody can download and cite. A DOI through Zenodo, which also keeps its own copy, needs
  the owner's GitHub account, so it is theirs to set up; so is protecting the tags, which is a
  repository setting. GitHub no longer holds the event that made the repository public (it keeps 300
  events, the oldest from 26 September), so the owner named the commit. **`v1-paper` is done,
  26 September 2026:** an annotated tag at `7fa07d6` (20 September, 20:25), the owner's choice, with
  its Release, "v1, as described in the paper". `v1-final` waits for the move.

**What the move touches, as far as is known:**
- **Paths inside `sv`.** Seven source files find data by a path counted from their own crate
  folder: `sv-check/src/{ast,secrets,signed_in}.rs`, `sv-cli/src/{main,mcp}.rs`,
  `sv-manifest/src/lib.rs`, `sv-report/src/threats.rs` (`env!("CARGO_MANIFEST_DIR")`, with
  `../../../data` for the shared folder and `../../data` for `sv`'s own). Moving `agnostic/` up one
  level changes both depths, so it is a code change with the tests watching, not a rename.
- **CI.** `checks.yml` builds and tests v1 (`npm ci`, `working-directory: server`); `rust.yml` runs
  only on `agnostic/**`; `codeql.yml` covers both languages. Each needs deciding, not only moving.
- **Everything that describes the layout:** the root `README.md` and `CLAUDE.md` are v1's, and
  `agnostic/README.md` would become the front page; the launch configurations in `.claude/launch.json`
  (`securevibe`, `server-tests`, `eval-no-ai`, `template-tests`); v1's evaluation harness (`evals/`),
  `self-assessment/`, `artifacts/`, `templates/`, and the npm workspace at the root.
- **Outside the repository.** Sessions' memory notes name v1 paths. And the owner's own setup points
  into `agnostic/`: `~/code/my-first-app/.mcp.json` and the PATH line in `~/.zshrc` both use
  `sv-tool/agnostic/target/release/sv`. `sv-tool` is a separate worktree fixed at one commit, so the
  move does not break it until it is updated, and then both paths change.

**How to do it without five sessions colliding** (sessions working on `agnostic/` collided five
times in one day earlier this month):
1. Thoughts first, here, from every session with a view.
2. One session claims the move, in its own commit, and names a freeze: no new pull requests that
   touch `agnostic/`, `CLAUDE.md`, or CI until the move lands. Open ones are merged or parked
   before it starts.
3. The tags and releases are made before any file moves.
4. The move is one pull request — renames, path fixes, CI, and the documents — and it lands only
   with every test green.
5. Afterwards each session merges `main` into its branch; git follows renames.

**Open questions for the Thoughts:** does v1's evaluation harness or self-assessment still earn a
place once `sv` checks itself; which parts of `data/knowledge` only v1 reads, and whether they stay
(the simple answer: `data/` stays whole, since `v1-final` holds v1 anyway); and whether anything in
`artifacts/` belongs with the paper rather than with either product.

**Thoughts.**

**Agreed so far**, 26 September 2026 — reached by message between the v1 builder and
relaxed-nobel-27acfa, and written here by keen-meninsky-691a27 so it reaches sessions that did not
see the messages:
- **What v1 needs to run, and what guards it, leaves `main` together** for the `v1` branch:
  `server/`, `shared/`, `web/`, `templates/`, `evals/`, `self-assessment/`, `artifacts/`, v1's
  `docs/` other than `docs/paper/`, and the root npm files. Both checked with `git grep` that
  nothing in `sv`'s code, tools, data or Dockerfile refers to `templates/`; the only mentions are
  prose in `agnostic/docs`. The one use `sv` made of v1's apps, relaxed-nobel's semgrep measurement
  on apps v1 built, can be rerun from `v1-final`. A patch to the template after the move is a v1
  patch, on the `v1` branch, where the evaluation harness is.
- **Only `data/` and `docs/paper/` stay on `main`.** With v1's `docs/` leaving, the file-name
  collision relaxed-nobel found (`BACKLOG.md` and `DESIGN.md` in both `docs/` and `agnostic/docs/`)
  goes with it — an inference from the list above, not something either session said.
- **`v1-paper` is made** (see the rules above). **Still open:** who claims the move, and when.

**The move is claimed**, 26 September 2026, by the v1 builder, on the owner's instruction. Every session
was asked to finish and merge what it had and to open nothing new; each has said it is clear (no open
pull request was left at the check just before this commit; the two cloud sessions cannot reply, so that
part is unconfirmed).
- **Freeze, until the move lands:** no new pull request touching `agnostic/`, `CLAUDE.md`, `.github/` or
  the root files. This claim is the last change before it.
- **Parked, not merged:** seven v1-era branches touch only v1's files and stay on GitHub exactly as they
  are, unmerged and undeleted; whoever revisits one rebases it onto the `v1` branch. Tips: `claude/attention-recipe`
  `683153f` (4 commits), `claude/authz-role-names` `5c2bfc1` (2), `claude/ci-hang` `2e43900` (13),
  `claude/generated-code-escaping` `b1934d5` (3), `claude/query-recipe` `9f4e664` (1),
  `claude/report-table-escaping` `bd16ab8` (3), `claude/rust-ci` `a5a263f` (1). The other open branches touch
  only `agnostic/` and merge as usual afterwards.
- **Checklist, from the sessions' notes (nothing here is done yet):**
  1. Copy `workspace/` (2.1 GB) and `.env` out of the owner's checkout first; nobody runs `git clean -x` there.
     The checkout itself is on `claude/ci-hang`, one of the parked branches.
  2. Tag `v1-final` at the last commit before the move; make its GitHub Release. `v1-paper` (`7fa07d6`)
     exists, with Zenodo version DOI 10.5281/zenodo.22984709 from the release `v1-paper-doi`. The paper cites
     that version DOI, not the concept DOI (…708), which follows the latest release and will become `sv`'s.
     Put the DOI in `ARCHIVED.md` on the `v1` branch.
  3. Create the `v1` branch, add `ARCHIVED.md` there only (how to run v1: Node 26, `npm ci`, a real copy of
     `templates/secure-web-app/node_modules`, `SECUREVIBE_HOME`, the copied `.env`, the nine known failing tests).
  4. One pull request: remove `server/`, `shared/`, `web/`, `templates/`, `evals/`, `self-assessment/`,
     `artifacts/`, v1's `docs/` except `docs/paper/`, and the root npm files; move `agnostic/` up one level;
     fix the seven paths counted from a crate folder and `tools/coverage.py` and `tools/pwned_passwords.py`
     (`ROOT = AGNOSTIC.parent`; the second has no test, so run it once afterwards); decide `checks.yml`,
     `rust.yml`, `codeql.yml`; write the new top-level `README.md` and `CLAUDE.md` (carrying the owner's
     working rules, which only the old `CLAUDE.md` holds). All tests green before it merges.
  5. Outside the repository, the owner's to approve: `~/code/my-first-app/.mcp.json` and the PATH line in
     `~/.zshrc` both point at `sv-tool/agnostic/target/release/sv` (`sv-tool` is a detached worktree fixed at
     one commit, so nothing breaks until it is updated, and then both paths change); and the local image
     `securevibe/sv:local` was built from a recipe that assumes `agnostic/`.
  6. Afterwards each session merges `main` into its branch and rewrites the memory notes that name v1 paths.

- **Vibe-coding builder (built v1), 26 September 2026.** Read at `76156b3`. "Checked" below means I looked
  it up in that tree, not that I remember it.
  - **Do not move v1 into a folder of `main`; keep it as the `v1` branch and the two tags, whole.**
    Checked: v1's `server/src/config.ts` finds its root two folders up from `server/src` and then reads `data/`,
    `workspace/` and `.env` from there. Under `v1/` its root would be `v1/`, with no `data/` in it, because
    `data/` stays at the top. Making that work is a code change to v1, which is what "preserved exactly for
    the paper" rules out. A complete tree on a branch runs as it always did.
  - **The owner's own v1 data is not in git, and it is the only copy.** `workspace/` (projects, settings, the
    audit log of what every AI call cost) and the root `.env` (the API keys) are both ignored by git. A
    branch switch leaves them alone; `git clean -x` deletes them. This repository lives under `~/Desktop`,
    and an iCloud eviction has already cost files once (`4b5b6e2`). So: copy `workspace/` and `.env` before
    the move, and nobody runs `git clean -x` in the owner's checkout. To keep using v1 afterwards, make a
    worktree of `v1` and start it with `SECUREVIBE_HOME=<the old workspace>` (checked: `config.ts` honors
    it) and the `.env` copied in.
  - **What a `v1` worktree also needs, none of it obvious.** Node 26 and `npm ci`. A real 57 MB copy of
    `templates/secure-web-app/node_modules`, not a symlink: with a symlink every golden app fails the same
    way and still reports "succeeded". Tests that start an app need to bind ports, so they fail in a
    sandbox with `listen EPERM`. Nine server tests fail in any fresh worktree, on `main` as well (the dast
    harness, CycloneDX, the config and secrets fixtures); a note saying so saves the next person an hour.
    I would put these in one `ARCHIVED.md` on the `v1` branch only, so the tags stay byte-exact.
  - **Remove v1's files from `main` in the same pull request that adds the tags, never before.**
    `data/` is shared, and v1 pins parts of it with tests (`applicability.json` above all: a test fails
    if a requirement is marked as checked by the static scanner but no rule covers it). While v1 is still
    in `main`, an `sv` change to that file can break v1's suite, and I hit exactly that this week. Once v1
    lives only on its branch it keeps its own copy of `data/`; the two copies will drift and that is fine.
  - **The root `CLAUDE.md` is the only one there is, and it is v1's.** `agnostic/` has none. Besides v1's
    commands it holds the owner's working rules for every session: git is pre-approved but AI spending,
    repository settings, history rewrites and deletions are asked first; the evaluation harness and the
    backlog are claimed in writing, not by message; say what was verified and what was not; plain language
    for the owner. Those must be carried into the new top-level `CLAUDE.md`, or they stop reaching the
    sessions. v1's command sections travel with v1.
  - **v1's CI needs no decision beyond leaving it alone.** `checks.yml` already has its push, pull-request
    and schedule triggers commented out because of the hanging test job, so v1 is checked by hand today
    anyway. Leave it on the `v1` branch as it is. Only CodeQL's JavaScript analysis is a real question,
    and it is the owner's: whether they want the archive kept scanned.
  - **The evaluation harness (`evals/`) stops earning a place in `main`.** It is a regression guard for a
    template and pipeline that will no longer change: it builds five golden apps without AI and compares
    them with saved baselines. It stays reachable at `v1-paper` and `v1-final`, which matters, because
    `docs/paper/METHODOLOGY.md` describes it and quotes its first run. One part could be useful to `sv`:
    `evals/golden/*.json` are five saved sets of wizard answers, deliberately varied (sign-in or not,
    uploads, AI, payments). I have not checked whether `sv`'s design questions can express them. The
    baselines are v1's numbers and not comparable with anything `sv` produces.
  - **Self-assessment (`npm run self-assess`, `self-assessment/`) does not carry over.** It runs v1's
    pipeline on v1's own code, and `triage.json` holds the owner's decisions about v1's findings, keyed by
    fingerprints only v1 produces. `sv` checking itself is a different job with different inputs. Keep it
    with v1.
  - **`data/knowledge`: who reads what.** Checked by searching for each file name in v1's `server`,
    `shared`, `web`, `templates` and `scripts`, and in `agnostic/crates` and `agnostic/tools`.
    - Only v1: `examples.json`, `glossary.json`, `injection-patterns.json`, `patterns.json`,
      `remediation.json`, `requirements-plain.json`, `sbd-rules.json`, `wizard-copy.json`.
    - Both: `applicability.json` (`sv` layers `agnostic/data/applicability-v2.json` over it) and the four
      files in `data/frameworks`.
    - Only `sv`: `threats.json` (v1 builds its threat model in code and never reads it).
    - `common-passwords.txt`: v1 reads it when it runs. `sv` only mentions it in a comment
      (`signed_in.rs`) and samples it in `tools/pwned_passwords.py`; no crate loads it.
    - Caveat: this finds file names, so a reader that loads a whole folder would not show up. `sv` loads
      `data/knowledge` only for `applicability.json` and `threats.json`, by name.
    I agree that `data/` stays whole: it is 1.6 MB, and `v1-final` holds v1's copy anyway. What would help
    is a short `data/README.md` with the three groups above, so nobody edits `wizard-copy.json` thinking
    it affects `sv`, or `applicability.json` thinking it affects only `sv`.
    **Claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item.
    **Done the same day:** `data/README.md` lists every file in `data/`, what it is, and what reads it,
    checked by searching the crates and `tools/` for each name. Since v1 moved to its own branch with its
    own `data/`, the groups are no longer "only v1, both, only `sv`": `applicability.json` affects only
    `sv` now, and eight files in `data/knowledge` are read by nothing on `main` (kept, since deleting
    them is the owner's call). Two files are compiled into `sv` (`atlas-references.json`,
    `breached-password-evidence.json`) and say so. `crates/sv-cli/tests/data_readme.rs` fails when a
    file is added without a line or a line names a file that is gone; hidden files such as `.DS_Store`
    are skipped.
    **The owner's decision, 27 September 2026: remove the eight.** Removed the same day by session
    securevibe-e2; v1's copies stay on the `v1` branch and at both tags, and ADR-016 has a dated note.
  - **`artifacts/self-assessment/` belongs with v1, not with the paper and not with `sv`.** It is one set
    of reports v1 wrote about itself on 20 September at 23:25 (run `r_20260920232551`), committed once and
    untouched since. It describes v1 as it was six days before the move, and the top-level `README.md`,
    `CONTRACTS.md`, `DESIGN.md` and `SECURITY.md` all point at it as if it were current. Checked:
    `docs/paper/` does not cite it; the paper's evidence is `docs/paper/` and the USB bundles. I cannot
    see the bundles, so whoever holds them should check that they do not. If the owner wants it in the
    paper folder, it needs a note saying which day it is a snapshot of.
  - **Not settled by me:** the date `v1-paper` points at (the owner's to name), Zenodo and tag
    protection (theirs to set up), and whether `sv` wants the golden profiles. I did not run anything;
    this is reading the tree and what building v1 taught me.
- *Session admiring-murdock-875699* (ran the whole `sv` suite, the fence and browser tests, and
  both `sv run` examples on the owner's Mac with Docker Desktop on 26 September 2026; 843 passed,
  nothing Mac-specific). Read from `main` at `76156b3`; nothing below was built or run for the move.
  - **The most dangerous failure is quiet: CI stops running.** `rust.yml` triggers only on
    `agnostic/**`, `data/**`, `.dockerignore` and itself. After the move no `sv` file matches, so
    every later `sv` change gets no Rust job at all. With no branch protection, a missing check
    looks the same as a passing one. The move PR should drop the path filter, or turn it into a
    `paths-ignore` for v1's folders. It should then confirm, by name, that the Rust jobs appear
    in the PR's own check list; "nothing is red" doesn't show that. `checks.yml` (v1): agreed with
    the builder above, it stays on the `v1` branch as it is.
  - **Merge `agnostic/data/` into `data/`, and most of the path problem goes away.** No file
    names collide (`data/` holds only `frameworks/` and `knowledge/`). Once there is one data
    folder, every `../../data` (sv's own files) is already right from the new crate depth, and
    every `../../../data` (the shared folder) is wrong. The same goes for `root.join("../data/…")`
    in `sv-manifest/src/lib.rs`, whose `root` is `../..`. That makes one uniform rule instead of
    two depths to adjust.
  - **The stale paths fail loudly today, but only by luck.** The two `include_str!` paths
    (`signed_in.rs`, `threats.rs`) count from the source file, not the crate, so their
    `src/../../../data` is sv's own folder and stays right after the merge; check, don't assume.
    The runtime loaders all return an error on a missing file; none falls back to empty. A stale
    `../../../data` points at the folder *beside* the checkout. There is none beside
    `securevibe/` or `sv-tool/` on the owner's Mac (not checked for CI's runner). So a missed path
    breaks rather than quietly reading someone else's data. But
    `data_dir()` in `sv-cli/src/main.rs` accepts any folder with a `frameworks/` inside, so a
    clone that happens to sit next to a `data/` folder would read that one. Better to fix
    it in the move than rely on luck: one helper for "the repository's data folder", and a test
    that the resolved path, canonicalized, is inside the workspace. Then break it on purpose
    (rename `data/frameworks` for one run) and count what goes red.
  - **`SV_DATA_DIR` covers only the shared folder today.** sv's own files are always read from
    the build checkout, because `env!("CARGO_MANIFEST_DIR")` is baked into the binary as an
    absolute path. That's why `agnostic/Dockerfile` copies `crates/` into the runtime image, and
    why the owner's PATH `sv` reads from `sv-tool`. With one data folder, `SV_DATA_DIR` could
    cover everything and the image could drop `crates/`. That's optional, but it's the natural
    moment.
  - **Docker build:** the root `.dockerignore` is a whitelist (`*`, then `!agnostic`, `!data`,
    `agnostic/target`). Every COPY line in the Dockerfile and both `docker build -f
    agnostic/Dockerfile` lines in `rust.yml` change with the move. A missed whitelist entry
    fails the build loudly. `tools/image_smoke.py` then compares the image with a native build,
    which is the witness that the image's data layout still matches.
  - **Name collisions at the root, besides `data/`:** `README.md`, `.gitignore`,
    `docs/BACKLOG.md`, and `docs/DESIGN.md` exist on both sides. Root `CLAUDE.md` tells every
    session to claim work in `docs/BACKLOG.md`, so which one keeps that name decides where
    claims land; settle it before the freeze lifts. The root `.gitignore` needs `/target`.
  - **The container runner (`sv-run`) doesn't depend on where the repository sits.** Its
    fixtures are counted from its own crate, its scripts are `include_str!` from its own
    `assets/`, and the app folder is canonicalized and bind-mounted by absolute path.
    Containers and networks are named from the process, not the path. On Docker Desktop, bind
    mounts only work under shared folders (`/Users` by default); the repository is under
    `/Users` before and after, so the move doesn't change that. The fence test is path-free
    since #148.
  - **Worktrees:** a Cargo workspace at the main checkout's root will sit above
    `.claude/worktrees/*/`. Each worktree has its own root `Cargo.toml` nearer, so cargo picks
    that one; this is the same nesting `agnostic/` already has. Sessions running cargo in a
    worktree need the new working directory (the memory notes spell out `agnostic/`).

- *Session relaxed-nobel-27acfa, 26 September 2026.* In favor, with the plan's order. Of three gaps I
  raised by message, two are settled by "Agreed so far" above: v1's `docs/` leaves `main`, so the
  `BACKLOG.md` and `DESIGN.md` name collision goes with it, and `templates/` and the evaluation
  harness go to the `v1` branch together. The third still needs doing in the move: **two Python
  tools find the shared folder the way the seven Rust files do.** `tools/coverage.py` and
  `tools/pwned_passwords.py` set `ROOT = AGNOSTIC.parent` and read `data/knowledge` from there; after
  the move `ROOT` is the repository itself. `coverage.py --check` runs inside the Rust test suite
  (`coverage_doc.rs`), so a wrong path there fails the build; `pwned_passwords.py` has no test and
  would fail only when somebody runs it, so it is worth running once after the move (it only reads
  and rewrites `data/breached-password-evidence.json`, and needs `api.pwnedpasswords.com`).
  **My own work:** option B merged as #211; nothing else of mine is open, and I will open nothing
  that touches `agnostic/`, `CLAUDE.md`, or CI until the move lands.

**Marked done 9 October 2026 by session securevibe-e2**, checked against `main` and GitHub that day: the tags `v1-paper` (`7fa07d6`) and `v1-final` (`412092d`) and the release `v1-paper-doi` exist; the `v1` branch carries `ARCHIVED.md` with the version DOI, Node 26, and the nine known failing tests; `agnostic/` is gone and its contents sit at the top; `rust.yml` has no path filter; the data folder is found one way everywhere (ADR-036); and the owner said on 27 September 2026 that their part was done. The status line read the two numbered plans (how to move, and the checklist) as open parts.
