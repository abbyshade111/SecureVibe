# A review of `sv` on 27 September 2026: faults, and what could be faster

**Status:** done, 28 September 2026

By session securevibe-e8, at
the owner's asking ("review sv and add any issues you find or ways to improve or optimize"). Read: the
entry points, the runner, every walker, the checks' hot loops, the MCP server, `Cargo.toml`, the
`Dockerfile`, and CI, on `main` at `4bee715`; then a release build timed on the Flask example and on this
repository, and one fixture built to settle a question the code could not. **Not claimed; each numbered
item can be claimed on its own.** Every item names where it is and how it was seen; a guess is marked as one.
Looked at and found sound, for the record: the MCP server's confinement of paths to its root (tested both
ways of escaping), the fence being verified rather than assumed, the adapters and the bundle refusing
symbolic links, and no panic anywhere on this repository's own 58,000 lines.

**Faults, most serious first.**
**Items 7, 1, and 3 claimed together on 27 September 2026 by session securevibe-e8**, at the owner's
asking: one walk of the app, with the link rule and the size cap in it, is one change. **Done the same day:**
`sv_scan::files::Listing`, one walk that no check repeats, links never followed and named, a 2 MB cap
for every reader, the bill of materials built once, and the corroborators reading each file once. `sv
report` on this repository goes from 2.86 s to 2.73 s; `sv check` is unchanged, because on trees this
size the time is in item 6, not in the walks. See DESIGN, "One walk of the app".
**Items 4, 5, and 8 claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to
continue with the backlog; one pull request each.
**Items 2 and 11 claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to
continue with the backlog; one pull request each.
**Item 2 was claimed twice**, a minute apart, and neither claim was on `main` when the other was made:
by session securevibe-e2 at 03:11 UTC (pull request #328) and by session securevibe-e9 at 03:13 UTC
(#329, which reached `main` first). securevibe-e2 had already built it by the time this was seen: branch
`claude/securevibe-e2-run-limits`, a time limit on the test suite and on every Docker call, Ctrl-C and
`kill` removing the run's containers, and each run removing what an ended run left, with tests against
real containers. The owner first chose that work (#331), but securevibe-e9's own had already reached
`main` (#332) before either session saw the other's. **The owner's decision, later the same day: #332
stays, #331 is closed, and the two things only #331 had are ported onto #332's code:** a
`test-time-limit` setting in `[stack.run]`, and cleanup after a run killed outright (everything a run
starts labeled with the machine and process, and the next run removing what an ended process left, and
saying so). **That port claimed on 28 September 2026 by session securevibe-e2.**
**Done the same day:** see DESIGN, "A run has an end, and Ctrl-C cleans up", the part headed "Later the
same day".
1. **Every walker but two follows symbolic links, out of the app and round in circles.** Reproduced with
   a fixture: an app whose `vendor-link` points at a folder outside it, and whose `src/loop` points at
   `..`. `sv check` read the outside folder's `settings.py` and reported its finding, then reported it
   again at every level of the loop, about thirty times, under paths four hundred characters long
   (`src/loop/src/loop/…/vendor-link/settings.py`). It finished in a second only because the operating
   system stops following links after thirty-two levels; nothing in `sv` did. `adapters.rs:730` and
   `bundle.rs:315` already refuse links, each with its reason; `ast.rs` (the code rules), `secrets.rs`,
   `sv-scan/src/lib.rs` (the corroborators), `suite.rs`, and `ecosystems.rs` do not. Reading outside the
   app is the promise `sv` makes about the folder it is given, broken by any link the app's author or its
   AI tool left. Fix: one rule where `skip_dir` lives, applied by every walker: a link is not followed,
   and is listed once as not read, so a linked `vendor/` is a named gap rather than a silent one. Test
   with this fixture, and count: five walkers should go red when the rule is removed.
   **Done on 27 September 2026 with item 7** (DESIGN, "One walk of the app"; noted here on 5 October 2026, when a
   backlog sweep found this item still read as open): `sv_scan::files::Listing` is the one walk, a link is never
   followed and is named once as a gap, and the fixture is the test
   `a_link_out_of_the_app_and_a_loop_are_listed_once_and_never_followed` in `crates/sv-scan/src/files.rs`.
   **Part status:** done, 27 September 2026
2. **`sv run` has no time limit, and an interrupted run leaves its containers behind.** Every Docker
   call goes through `output_of` (`sv-run/src/lib.rs:327`), which waits forever; the app's own test
   suite is `docker exec sh -c <test>` (`docker.rs:424`) with nothing bounding it, so a suite that hangs
   hangs `sv report --run` with it. Cleanup is `Teardown`'s `Drop` (`docker.rs:1123`), which runs on
   every return path and not when the process is killed by Ctrl-C, since a signal ends a Rust process
   without unwinding: the app, the sidecar, the stand-ins, and the `--internal` network stay, under
   names that carry the process id, so they accumulate. The second half is reasoned from the code, not
   reproduced. Fix: a stated cap on the test command (`timeout` inside the container, say ten minutes,
   with the cap in the report when it fires, since a suite that was cut short credits nothing), a
   wall-clock limit per Docker call, and a Ctrl-C handler that runs the teardown; failing that, a
   `sv run --clean` that removes everything named `sv-…`.
   **Done on 28 September 2026 by session securevibe-e9:** every Docker call is limited to 20 minutes and
   the test command to 10, a suite stopped at the limit credits nothing and the report says it was
   stopped, and Ctrl-C lets the run remove its containers and network before `sv` exits. Tested against
   real Docker, Ctrl-C included, and each guard broken on purpose turns at least two tests red. See
   DESIGN, "A run has an end, and Ctrl-C cleans up". `sv run --clean` was not needed for Ctrl-C; a run
   ended by `kill -9` still leaves its containers, and the DESIGN section says how to list them.
   **Part status:** done, 28 September 2026
3. **No size limit in the code-rule walker or the corroborator walker.** `secrets.rs` stops at 2 MB
   (`MAX_FILE_BYTES`) and says so. `ast.rs:1313` reads any file whole and hands it to tree-sitter, so a
   50 MB minified bundle or a generated file is parsed in full; `sv-scan/src/lib.rs:490` reads every
   source file whole and keeps all of them in memory for the run (`files.push((language, relative,
   contents))`). Fix: the same cap, reported as *not read, too large* rather than skipped, which is the
   honesty rule; and the corroborators reading one file at a time.
   **Done on 27 September 2026 with item 7** (DESIGN, "One walk of the app"; noted here on 5 October 2026): the
   listing holds every file's size, and a file over `MAX_FILE_BYTES` (2 MB) is not read as text by any check and is
   reported as not read, too large.
   **Part status:** done, 27 September 2026
4. **Options are read as folders.** `sv check --help` says "--help is not a folder"; `sv scope
   --nonsense` says "no securevibe.toml in --nonsense"; there is no `sv --version` at all (the version
   appears only in a bundle's listing). `main.rs` dispatches on the first word and hands the second to
   the command as a path. Fix: a word starting with `-` is an option, an unknown one is an error that
   names the command's options, `--help` works after any command, and `sv --version` prints the version
   and the commit the build was made from, which the bundle already knows how to find.
   **Done on 28 September 2026 by session securevibe-e9:** every command's options are in one table,
   `COMMANDS` in `main.rs`, checked before the command runs. An unknown option is refused with the
   command's options and its usage; so is a second folder, a word where a command takes none, and an
   option missing its value. A folder whose name starts with `-` is named as `./-name`, which the
   message says. `--help` or `-h` after any command shows that command's usage and runs nothing.
   `sv --version` prints the version and the commit. `crates/sv-cli/tests/options.rs` holds it; each
   part, broken on purpose, turns at least two of its tests red, except `--version`, which one test
   holds.
   **Part status:** done, 28 September 2026
5. **A bad edit to a compiled-in data file makes `sv run` panic.** `signed_in.rs:1135-1153` uses
   `expect` while reading `data/breached-password-evidence.json`, which is compiled in with
   `include_str!`; the file is checked by a test, so this reaches an owner only from a source build with
   the file broken. Low. A panic in a probe run should be *not assessed* with the reason, like every
   other failure there. **Done on 28 September 2026 by session securevibe-e9:** the file is read by
   `breached_seen_in`, which says what is wrong with it (not JSON, evidence for another password, no
   count, no date), and V6.2.12 is then *not assessed* with that reason, whatever the app answered;
   the rest of the run goes on. Two tests in `signed_in.rs` hold it, each failing when the password
   match or the count is taken out.
   **Part status:** done, 28 September 2026

**What could be faster.** Timed with a release build: `sv check` on the five-file Flask example takes
about a second, `sv check .` on this repository about three, `sv report` on the example about one. None
is slow for a person at a terminal. Two of them are slow for an AI tool calling the MCP server after
every change, and the first is the reason.
6. **Everything is loaded and compiled again on every command and every MCP call.** `assemble_report`
   (`main.rs:1848-1863`) loads the four framework files (234 KB of JSON), both rule files, and the
   adapters (371 KB), and compiles every tree-sitter query (twelve rules across fourteen languages) and
   every regex, each time it runs; `securevibe_explain` reloads the frameworks per call (`mcp.rs:632`).
   The `Server` struct holds only its root. Fix: load once per process, in `Server` for the MCP server
   and at the top of `main` for the CLI, and measure the difference; most of the second above is this.
   **Claimed 27 September 2026 by session securevibe-e8**, at the owner's asking, in branch
   `claude/load-once`. **Done the same day**, and the premise corrected: the JSON was 5 ms of the
   second, and 873 ms was tree-sitter compiling 143 queries in fifteen languages for every command.
   Queries now compile the first time their language is met and are kept for the process; the MCP
   server loads everything once in `Server`. `sv check` on a small app 957 ms → 30 ms; on this
   repository 2.33 s → 1.93 s. See DESIGN, "The second before the first file".
   **Part status:** done, 27 September 2026
7. **The app folder is walked six times per report, the bill of materials is built two or three
   times, and every source file is lowercased once per signature.** The walks: secrets, the code
   rules, the corroborators, the tools' file list, the test finder, and the ecosystems. `sbom::build`
   runs in `versions_pinned` (through `check_dir`) and again in `assemble_report`; `sv check` builds it a
   third time (`main.rs:1222`). In `sv-scan/src/lib.rs:298`, `contents.to_lowercase()` sits inside the
   loop over signatures, so with about thirty signatures the whole source is lowercased about thirty
   times. Fix: one walk that yields the file list once and is handed to each check, one bill of
   materials passed down, and one lowercasing per file. This is the change that would matter on a large
   app; measure on one before and after.
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: all
   three are overtaken. The folder is walked once (`sv_scan::files::Listing`, item 1's note above, DESIGN "One
   walk of the app"), and the six readers take that one listing; `sv-scan/src/lib.rs` lowercases each file once,
   before the loop over signatures; and `sbom::build` is called once per command (`sv run`, `sv sbom`), the report
   and `sv check` taking the bill of materials they built rather than making another.
   **Part status:** done, 27 September 2026
8. **Regexes compiled inside hot loops.** `logs.rs` compiles four patterns per log line
   (`common_format`, `timestamp`, `has_place`, lines 231-320), `ai.rs:1080` one per (line, word) pair,
   `secrets.rs:268` and `:331` one per file, `signed_in.rs:4336-4355` one per page. `probes.rs:1222`
   shows the fix: a `LazyLock` static, compiled once.
   **Done on 28 September 2026 by session securevibe-e9:** every fixed pattern in `logs.rs`,
   `secrets.rs`, and `signed_in.rs` is a `LazyLock` static, and `ai.rs`'s `has_word` matches a word
   by hand, since its words include the run's own token counts. A test holds `has_word` to the
   pattern it replaced, on lines with capitals, accented letters, and emoji. Timed with a release
   build on the same inputs, before and after: reading 20,000 lines of an app's output for the AI
   checks, 16.7 s to 0.05 s; the log checks 200 times over, 0.42 s to 0.004 s; the credential scan
   of 2,000 small files, 3.4 s to 0.04 s; redacting a failing test's output 2,000 times, 0.29 s to
   0.05 s. The first was the only one a person would have waited on, and only for an app that writes
   a lot while it runs.
   **Part status:** done, 28 September 2026
9. **The reports are large for what they say.** For the five-file example: `compliance.md` 160 KB,
   `report.html` 191 KB, `report.json` 367 KB, because each of about six hundred requirements carries
   its full text in every rendering, applicable or not. For a person the HTML is fine. For the AI tool
   reading `report.json`, and for anyone diffing two reports, the text once per id, or the
   not-applicable rows collapsed, would cut most of it. The owner's call on what the reading experience
   should be.
   **Claimed on 28 September 2026 by session securevibe-e10**, in branch `claude/report-shape`. **The
   owner's decisions, the same day:** in `report.json`, each requirement's text once, in a lookup
   table by id, which every section points to; in `compliance.md`, the requirements that apply grouped
   by chapter, each chapter's counts in one row (applies and checked, applies and not verified, does
   not apply, not placed yet), with the full text in an appendix; and a requirement that does not
   apply shown by its id and the reason, without its text. The HTML page keeps the full text.
   **Done the same day**, and the premise corrected: only the tests worth writing repeated the
   text, so `report.json` went from 367 KB to 334 KB, and `compliance.md` grew from 160 KB to
   169 KB while the part read before its appendix went from 63 KB to 14 KB. See DESIGN, "The
   report's shape". Not done, and not decided: `only_you_can_check` in `report.json` repeats
   word for word 50 entries of `questions_for_you` (27 KB on the example).
   **The owner's decision, the same day: drop the duplicate. Claimed by session securevibe-e10**, in
   branch `claude/only-you-once`.
   **Done the same day:** `report.json` names them as `only_you_can_check_ids`, each a question in
   `questions_for_you`; 334 KB to 306 KB on the example. See DESIGN, "The report's shape".
   **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: both of
   the owner's decisions above are built, as the notes above say; nothing in this part waits on a build.
   **Part status:** done, 28 September 2026
10. **No release profile.** `Cargo.toml` sets none, and the binary is 35.6 MB. `lto`, `codegen-units =
    1`, and `strip = true` are the usual settings for a tool built once and shipped, and typically halve
    the size; the Docker image and the "download later" packaging item both carry the binary. Measure
    size and speed before and after, since `lto` can also lengthen CI's build.
    **Claimed on 28 September 2026 by session securevibe-e10**, at the owner's asking, in branch
    `claude/release-profile`. **Done the same day**, and the premise corrected: 27 MB of the 35.7 MB is
    the parse tables of the fifteen tree-sitter grammars, and 4.9 MB is code, so no setting can halve
    it. `lto` and one code-generation unit cut 2.4 MB for a clean build 30 s longer and no change in
    speed; the profile keeps `strip = true` only, 34.5 MB. See DESIGN, "A release profile".
   **Part status:** done, 28 September 2026

**Smaller.**
11. **The runtime image runs as root.** `Dockerfile` sets no `USER`; the image reads mounted folders
    and writes reports into them. A non-root user, or `--user` in the documented `docker run` line,
    keeps a mistake from writing into the owner's folder as root. (`safe.directory` for git is already
    handled.)
    **Done on 28 September 2026 by session securevibe-e9:** the image runs as its own user, 10001,
    never root; `--user "$(id -u):$(id -g)"` on Linux still makes it the owner, as the README and
    GETTING-STARTED say. `tools/image_smoke.py` checks the image's user is not root, and its
    `safe.directory` check now names root explicitly, since the image's own user could not read the
    test folder. Not built in the session that made the change (its sandbox cannot reach the Debian
    mirrors from a build); CI's image job builds and drives it.
    **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: the
    image runs as its own user, and CI's image job builds and drives it on every pull request (`tools/image_smoke.py`,
    which checks the user is not root).
   **Part status:** done, 28 September 2026
12. **`sv` holds apps to V15.2.1 and does not hold itself.** CI has no `cargo audit` or `cargo deny`
    step; Dependabot proposes updates but compares nothing; the v2 self-assessment ran the OSV
    comparison once, by hand. A weekly job running `sv audit .` against a downloaded OSV export, or
    `cargo audit`, belongs with the weekly review entry above.
    **Claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to pick an item.
    **Done the same day:** `.github/workflows/audit.yml` runs `sv audit .` against OSV's crates.io export
    weekly and when a lockfile or manifest changes. `sv audit` now respects `not-the-app` and exits 0,
    1, or 2 for clean, found, and not fully compared. `sv`'s 68 crates matched none of 2,858 records.
    See DESIGN, "`sv` audits its own dependencies, weekly". Three faults found on the way are entries
    of their own below: the report's bill of materials ignores `not-the-app`, an ecosystem counts as
    covered by a database that only mentions it in passing, and one vulnerability under two names is
    counted twice.
   **Part status:** done, 28 September 2026
13. **`signed_in.rs` is 15,351 lines**, with 231 tests and one fake app carrying about eighty flaw
    switches; `ai.rs` is 3,338. A session touching one check reads all of it, and every session's
    change to a check lands in the same file, which is where this week's merge conflicts were. Split by
    check (sign-in, sessions, admin, passwords, uploads, flows, codes) with the fake app as a test
    module of its own. No behavior changes; the 231 tests are the guard.
    **Done on 28 September 2026, and the freeze is lifted:** `crates/sv-check/src/signed_in/` is fourteen
    files, none over 2,001 lines, with the same 233 tests; see DESIGN, "The signed-in checks, one file per
    area". The changes waiting on the freeze (securevibe-e9's V14.2.2 and V8.2.3, and the nine signed-in
    partial checks) can go ahead, each in its area's file.

    **The owner asked on 28 September 2026 for this to be shared across several sessions.** The plan
    below is by session securevibe-e9, from the file as it stood on `main` that day: 15,463 lines,
    about 7,600 of checks and 7,900 of tests, 233 tests, and one fake app (`FakeApp` and `Flaws`, about
    1,450 lines) that nearly every test drives. **The file is frozen from the moment step 0 is claimed
    until step 2 is done:** no other pull request changes `crates/sv-check/src/signed_in.rs` or the
    folder that replaces it, so a fix to a check waits, or is made by the session holding that check's
    slice, in its slice's pull request. The freeze is what keeps several sessions moving the same file
    from spending their time on merge conflicts, which is the fault this item exists to fix.

    **Rules for every step.** Code is moved, never changed: no renames, no new logic, no reformatting
    beyond `cargo fmt`. The only edits allowed are `use` lines, `mod` lines, and widening a private item
    to `pub(super)` so a sibling file can reach it. Something two slices both use stays where it is
    (the shared plumbing, below) rather than being moved by either. A test that drives several areas at
    once (`each_flaw_is_found_by_its_own_rule_and_by_no_other`,
    `a_correct_app_raises_nothing_and_every_check_says_what_it_confirmed`,
    `an_app_with_every_flaw_at_once_has_every_one_found`, and the like) stays in `mod.rs`. Each pull
    request shows it moved and did not change: `git diff --color-moved=zebra -M origin/main` has no
    lines but moved ones and `use`, `mod`, and visibility lines, and the pull request says so. And
    each one keeps every test: the names from `cargo test -p sv-check --lib signed_in -- --list`,
    compared by their last part, are the same set before and after, 233 of them unless a step says
    otherwise. The usual checks (`cargo fmt --all --check`, `cargo clippy --all-targets -- -D
    warnings`, `cargo test --workspace`) pass. Merge `main` in before merging; a conflict in `mod.rs`
    is two sessions' `mod` or `use` lines, and keeping both resolves it.

    **Step 0, one session, alone, merged before step 1 starts.** Turn the file into a folder and move
    out what every slice depends on, so the slices after it touch only their own lines.
    - `git mv crates/sv-check/src/signed_in.rs crates/sv-check/src/signed_in/mod.rs` in a commit of its
      own with no other change, so git records a rename and `git log --follow` keeps the history.
    - `signed_in/fake_app.rs`, `#[cfg(test)]`: `FakeApp`, `Flaws`, the constants beside them, its `impl
      Http`, and the helpers every test uses (`users`, `accounts`, `run_against`, `run_with_users`,
      `rule_ids`, `verified_ids`, and the request helpers `cookie_value`, `decode`, `pairs`, `form`),
      roughly lines 7,609 to 9,220 today.
    - `signed_in/rules.rs`: the `Rule` constants and finding helpers of the "Findings" section, roughly
      lines 452 to 1,254.
    - Sessions, anti-forgery tokens, and requests from templates (roughly lines 122 to 451), the
      `Http` trait, `Outcome`, `run`, `run_with`, `sign_in`, and `sign_up` stay in `mod.rs`: they are
      the shared plumbing.
    - Record the 233 test names in the pull request, as the list the later steps compare against.

    **Step 1, in parallel, one session per slice.** Each slice is claimed on its own line below, in a
    claim commit of its own, and is one pull request: its functions move from `mod.rs` into its file,
    and the tests about them move with them into that file's own `#[cfg(test)] mod tests`, which uses
    `super::fake_app::*`. Line numbers are from 28 September and will have moved after step 0; the
    function names are what count.
    - a. `signin.rs`: `guess_once`, `forwarded_check`, `brute_force_check`, `plant_log_markers`,
      `default_account_check`, `password_in_url_check`, `sign_out_on_get_check`, `logout_check`, and
      the V6.3.1 wrong-password tests.
    - b. `sessions.rs`: `session_timeout_checks`, `minutes_text`, `session_checks`, `session_id_check`,
      `most_bits`, `invented_session_check`, `private_page_checks`, `points_at`, `clear_site_data_check`,
      `record_fields_check`, `SECRET_FIELD_NAMES`, and the session-timeout and private-page tests.
    - c. `passwords.rs`: `sign_up_only`, `account_works`, `describe_password`, `judge_breached`,
      `breached_seen_in` and the breached-password evidence beside it, `password_checks`,
      `exact_password_checks`, `password_field_checks`, `change_password_checks`,
      `reveals_account_check`, `same_shape`, `password_hint`, `delete_account_check`.
    - d. `codes.rs`: `reset_checks`, the `email_code_*` functions and `EmailCode`, `wrong_code`,
      `activation_checks`, `activation_code_check`, `code_patterns`, `reset_code`, `percent_decode`,
      `reset_code_check`, `TotpSignIn` and `totp_checks`, and the password-reset, emailed-code,
      activation, and two-factor tests. The largest slice; it may be split in two (emailed codes, and
      two-factor) by whoever claims it, saying so in the claim.
    - e. `uploads.rs`: the "Uploads" section's `GIF_MAGIC`, `Upload`, `multipart`, `send_upload`,
      `upload_checks`, `disposition_params`, `download_name_checks`, `served_upload_checks`,
      `client_side_validation_check`, and the upload tests.
    - f. `flows.rs`: `finished`, `take_steps`, `flow_checks`, and their tests.
    - g. `admin.rs`: `admin_checks`, `ROLE_FIELDS`, `signed_in_session`, `role_field_check`,
      `admin_action_checks`, `owned_checks`, `record_path`, `strip_origin`, and their tests.
    - h. `forgery.rs`: `forgery_check`, `referrer_policy`, `null_origin_check`, `simple_request_check`,
      `NullOriginApp` and its tests, and the WebSocket foreign-origin (V4.4.2) tests;
      `ws_handshake` and `websocket_session_checks` go with slice b unless its session says otherwise.

    **Step 2, one session, after every slice is merged.** What is left in `mod.rs` is the plumbing,
    `run_with` calling each slice, and the cross-area tests. Check no slice's file passed about 2,500
    lines, and split one that did the same way. Add a DESIGN section saying where each check now lives,
    and mark this item done with the final line counts and the final test count.

    **`ai.rs` (3,338 lines) is not part of this.** It can be split the same way afterwards, as its own
    item.

    **Claims:**
    - Step 0: **claimed on 28 September 2026 by session securevibe-e2**, at the owner's asking to pick
      another item, in branch `claude/securevibe-e2-split-step0`. `signed_in.rs` is frozen from this
      claim's merge until step 2 is done.
      **Done the same day:** `signed_in/mod.rs` (13,192 lines), `signed_in/fake_app.rs` (1,609), and
      `signed_in/rules.rs` (664, the `Rule` type, `finding`, and the sixty rules); the 233 tests are the
      same set and all pass. Three things for step 1:
      - `rules.rs` took only the rules. The password constants and helpers after them (`COMMON`,
        `BREACHED`, `BREACHED_EVIDENCE`, `breached_seen_in`, `with_commas`, `long_date`, `random_like`,
        `context_password`, `DEFAULT_ACCOUNTS`) stay in `mod.rs` for slices a and c to take.
      - `BREACHED_EVIDENCE` is an `include_str!` with a path relative to its file; it gained a `../` when
        the file moved down a folder, and keeps working from any file beside `mod.rs`.
      - `tools/coverage.py` now reads every file under a crate's `src`, subfolders included, and leaves
        out a file declared `#[cfg(test)] mod name;` (as `fake_app.rs` is). Before, it read `src/*.rs`
        only, and moving the rules down a folder made it lose every signed-in check.
    - Step 1, slice d (`codes.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking, in branch `claude/securevibe-e2-split-codes`. One file, not split in two.
      **Done the same day:** `signed_in/codes.rs`, 3,300 lines with its 64 tests; `mod.rs` is 1,442, and its
      tests are the 12 that exercise several areas at once, beside the shared test helpers. With each of
      the nine checks made to return at once, the moved tests catch every one. `codes.rs` is past the
      2,500 lines step 2 checks for, so step 2 should split it, into emailed codes (reset, sign-in codes,
      activation) and two-factor, as the plan allows.
    - Step 1, slice a (`signin.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-signin`.
      **Done the same day:** `signed_in/signin.rs`, 1,140 lines with its 21 tests; `mod.rs` is 4,729.
      `run_with`, `run_keeping_app`, and `seeded_with` stay in `mod.rs`'s tests, since slice d's tests
      use them too. With each check made to return at once, the moved tests catch `guess_once`,
      `forwarded_check`, `brute_force_check`, and `logout_check`. `default_account_check` (V6.3.2),
      `password_in_url_check` (V14.2.1), `sign_out_on_get_check` (V3.5.3), and `plant_log_markers` are
      caught only by cross-area tests in `mod.rs`, which was so before the split.
    - Step 1, slice c (`passwords.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-passwords`.
      **Done the same day:** `signed_in/passwords.rs`, 1,954 lines with its 33 tests; `mod.rs` is 5,859.
      The breached-password evidence came along, and its `include_str!` path still works from beside
      `mod.rs`. `run_signing_up`, `run_signing_up_with`, and `with_words` stay in `mod.rs`'s tests,
      since slice d's tests use them too. With each of the eight checks made to return at once, the
      moved tests catch every one.
    - Step 1, slice b (`sessions.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-sessions`. A move
      only, with `ws_handshake` and `websocket_session_checks`: securevibe-e9's V14.2.2 and V8.2.3
      changes to the caching and record-field checks stay with securevibe-e9, after it.
      **Done the same day:** `signed_in/sessions.rs`, 2,001 lines with its 41 tests; `mod.rs` is 7,800.
      Shared and so left in `mod.rs`'s tests: `timeouts` (slice d's `code_slow_run` uses it), and
      `WS_RULES`, `ws_run`, `ws_findings`, and `bearer_ws_users` (`forgery.rs` uses them). `most_bits` is
      in `sessions.rs` as planned and `pub(super)`, since the code checks use it too. With each check
      made to return at once, the moved tests catch six of the eight; `session_checks` (the cookie's
      attributes, V3.3.2 and V3.3.4, and its renewal at sign-in, V7.2.4) and `session_id_check` (V7.2.3)
      are caught only by four cross-area
      tests in `mod.rs`, which was so before the split. `private_page_checks` and
      `record_fields_check` are in `sessions.rs` now, for securevibe-e9's V14.2.2 and V8.2.3 changes.
    - Step 1, slice g (`admin.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-admin`. A move only:
      securevibe-e9's V8.2.3 change to `probe.role-field-trusted` stays with securevibe-e9, after it.
      **Done the same day:** `signed_in/admin.rs`, 1,034 lines with its 17 tests; `mod.rs` is 9,787. With
      each check made to return at once, the moved tests catch every one: `admin_checks` 3,
      `admin_action_checks` 6, `role_field_check` 4, and `owned_checks` 2, besides the cross-area tests.
      `role_field_check` is in `admin.rs` now, for securevibe-e9's V8.2.3 change.
    - Step 1, slice h (`forgery.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-forgery`.
      **Done the same day:** `signed_in/forgery.rs`, 777 lines with its 17 tests; `mod.rs` is 10,811. The
      WebSocket foreign-origin tests use `ws_run`, `ws_findings`, and `bearer_ws_users`, which stay in
      `mod.rs`'s tests for slice b and are `pub(super)`. Each check was made to return at once: breaking
      `null_origin_check` turns 5 of the moved tests red, and `simple_request_check` 4. `forgery_check`
      (V3.5.1) turns only the three cross-area tests in `mod.rs` red, none in `forgery.rs`: nothing
      tests it on its own, which was so before the split and is left for a change that may add tests.
    - Step 1, slice f (`flows.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-flows`.
      **Done the same day:** `signed_in/flows.rs`, 371 lines with its 8 tests; `mod.rs` is 11,578. With
      `flow_checks` made to return at once, 7 of the 8 go red (the eighth is the app with no flow), and
      none of the tests left in `mod.rs` does: the all-flaws and correct-app tests do not cover flows.
    - Step 1, slice e (`uploads.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
      owner's asking to pick another item, in branch `claude/securevibe-e2-split-uploads`.
      **Done the same day:** `signed_in/uploads.rs`, 1,261 lines with its 20 tests; `mod.rs` is 11,940.
      `MOST_UPLOAD_BYTES` came along, since only upload code uses it. `with_signup` stays in `mod.rs`'s
      tests, shared by several areas, and is `pub(super)` so a slice's tests can `use
      super::super::tests::with_signup`; other shared test helpers can be reached the same way.
    - Step 2: **claimed on 28 September 2026 by session securevibe-e2**, at the owner's asking, in branch
      `claude/securevibe-e2-split-step2`: `codes.rs` split in two, `mod.rs` tidied, a DESIGN section, and
      this item marked done, which lifts the freeze.
      **Done the same day.** `codes.rs` was split in four rather than two: two-factor out alone would have
      left 2,700 lines, past the 2,500 checked for, so it is split by area into `reset.rs` (692 lines),
      `activation.rs` (614), `totp.rs` (592), and `codes.rs` (1,426, the emailed sign-in code and what the
      three email flows share). Each moved check, made to return at once, turns the tests in its new file
      red. `mod.rs` (1,471) lost two headings with nothing under them and gained a map of the files at its
      top, and DESIGN has the same map. Final lines: `mod.rs` 1,471, `fake_app.rs` 1,609, `rules.rs` 664,
      `signin.rs` 1,140, `sessions.rs` 2,001, `passwords.rs` 1,954, `reset.rs` 692, `codes.rs` 1,426,
      `activation.rs` 614, `totp.rs` 592, `admin.rs` 1,034, `forgery.rs` 777, `flows.rs` 371, `uploads.rs`
      1,261; 15,606 in all, against 15,463 before. The difference is the new `mod`, `use`, and test-module
      lines, blank lines between moved blocks, and the map, less the two headings. Tests: the same 233. Found on the way: `tools/pwned_passwords.py` still read the breached
      password from `signed_in.rs`, which has not existed since step 0, and matched only `const BREACHED`,
      not `pub(super) const BREACHED`; it has no test, so it would have failed the next time it was run.
      Both fixed, and the reading part run to show it finds the password the evidence file records.
      `docs/PARTIAL-CHECKS.md` still names `signed_in.rs` in about sixty places; left as it is, since the
      name still points at the folder and securevibe-e9's open work edits that file.
    **Settled 8 October 2026** (session securevibe-e2, from the roadmap, Phase 1 item 3), read against `main`: the
    split is built, as the note above says: `crates/sv-check/src/signed_in/` holds the checks by area, with a map of
    the files at the top of `mod.rs`.
   **Part status:** done, 28 September 2026
