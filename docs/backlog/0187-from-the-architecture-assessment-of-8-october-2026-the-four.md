# From the architecture assessment of 8 October 2026: the four costs worth paying down

**Status:** partly done: 5 of 12 parts done, 1 claimed, 5 open, as its markers read on 8 October 2026

A read-only assessment of
`sv`'s shape (the run harness, the MCP server, the check pipeline, the test suite and CI) made after the review of
the same day, at the owner's asking; its file is with the owner. The design is sound where it matters (a pure
applicability engine, one place that decides each requirement's status, the `Http` seam, the fence, four gates
holding a citation to its claim), and three weeks of building have left four costs. **Items 1 to 4 claimed on 8
October 2026 by session securevibe-review**, at the owner's word ("can you start on the 4 costs worth paying down
now"), one pull request each in the order below; the rest are for any session. Appended here rather than put at the
top, so that two sessions claiming on the same day stop colliding on the same lines (see item 11).
1. **The test suite's time is in five tests and a profile setting.** Timed one test at a time: the `sv-check` unit
   binary's 1,263 tests take 1,263 s single-threaded (531 s on four CPUs, of the whole suite's 896 s), 1,022 s of
   them in `signed_in`. `a_crash_never_turns_a_finding_into_a_pass` takes 405 s running its scenarios one after
   another, while `a_crash_on_a_correct_app_raises_no_finding` beside it runs the same kind of sweep on scoped
   threads; four `signed_in::once` tests take 60 s each because each runs the whole suite to reach one check; the
   46 `ast` tests take 126 s because each case reloads and recompiles every query from `data/ast-rules.json`, and
   32 s with dependencies compiled at `opt-level = 2` (measured). Four changes, no behavior change: the profile
   setting in the workspace `Cargo.toml`; a `OnceLock<AstRules>` in the `ast` tests; the crash sweep on scoped
   threads; the `once` tests calling the check's own function. And `rust.yml`'s `push` trigger limited to `main`,
   since every pull-request commit runs the 15-minute test job twice today (push and pull_request), and branch
   protection waits for both. Branch `claude/securevibe-review-suite-speed`. ADR-051 unchanged: every pull request
   commit and every commit on `main` is still tested.
   **Done the same day** (DESIGN, "The test suite's time: five tests and a profile setting"): the `sv-check` unit
   binary from 531 s to 92 s on four CPUs, the `ast` tests from 126 s to 1.9 s, the crash sweeps from about 400 s
   on the critical path to 80 s. The crash sweep itself is unchanged: it already ran on scoped threads, and the
   profile setting made each of its suite runs cheaper.
2. **Two pure refactors in the harness and the MCP server.** The hardening flags (`--read-only --cap-drop ALL
   --security-opt no-new-privileges`) are written out 12 times in `docker.rs` and once in `install.rs`; they belong
   in `prepared`, where ADR-019 already put the limits (branch `claude/securevibe-review-hardening-once`).
   **The first half done the same day** (DESIGN, "The hardening in one place"; ADR-019, Later, 8 October 2026):
   `HARDENING` put on in `prepared` for every `run` and `create`, the eleven copies and `install.rs`'s gone, and the
   no-sidecar fallback through `prepared` too, so it gains the limits and the run label it lacked. `mcp.rs`
   is 7,202 lines in one file, 62% tests, with natural seams (protocol, confinement, resources, the tool catalog,
   check rendering, report writing, the other tools); and the report-writing sequence (claim, assemble, manifest
   changed, refuse older, write, seal, written) is in `cmd_report` and again in `write_report_into`, so a step
   added to one and not the other is a silent difference between what the person gets and what the AI tool gets.
   One pipeline, a `ReportOptions::reading_only(caller)` for the eight hand-written "why not run" triples, and one
   list the three report-file-name lists derive from (branch `claude/securevibe-review-mcp-split`).
   **Second half done the same day** (DESIGN, "The MCP server in a folder, and one way to write a report folder"):
   `mcp.rs` is the folder `mcp/` (nine files, the tests their own); `report_folder::write_report_folder` is the
   one sequence `sv report` and `securevibe_write_report` both call; `ReportOptions::reading_only` and `asked_of`
   replace the seven hand-written triples (the MCP server's three sentences written over `reading_only`'s); and
   the five file names are `sv_scan::ecosystems::REPORT_FILES`, which the folder names, the seal's list, and the
   MCP server's resources derive from, with `sv-cli`'s table of renderers held to it by the compiler.
3. **`sv check` and `sv report` can exit differently on the same folder.** `cmd_check` runs the same five scanners
   but never `merge_same_place`, the test-code and bundled-library marks, or `review::apply`, and its exit code
   counts every finding, where `sv report`'s counts the findings left after a person's recorded false alarms. So
   `sv check --fail-on attention` can fail a CI pipeline on a finding the owner set aside. One `StaticScan` stage
   used by both. An exit code is a default that changes a conclusion: **`Status: proposed`, a Later entry on
   ADR-023**, made accepted in the pull request that builds it. Branch `claude/securevibe-review-static-scan`.
   **Done the same day** (ADR-023, Later, 8 October 2026; DESIGN, "One static stage for `sv check` and
   `sv report`"): `crates/sv-cli/src/static_scan.rs`, `StaticScan::read` and `settle`, called by both; `sv check`
   applies the manifest's reviews and says what was set aside and what does not count; the test shows the two
   exit alike before and after a review.
4. **The tier is not on the value, and the run's script lives in the container layer.** A `Verified` lands in
   *attested*, *stated*, *by hand*, or *documented* by which slice of `Inputs` it is passed in, assembled by hand
   in `main.rs`, and *attested* is told from *stated* by a string match on the check id; an enum on `Verified` and
   a `status_of(evidence)` function with unit tests per tier (branch `claude/securevibe-review-tier-on-value`).
   And `sv-run` depends on `sv-check`, the reverse of the stated layering, because `run_after_cleanup` (568 lines)
   is the whole run: which suites, in which order, as which user. Move the script into `sv-check` as a function of
   `Http` plus a `Services` struct, so it runs against the fake app without Docker and the Docker-only residue is
   the fence, limits, teardown, and install (branch `claude/securevibe-review-run-script`). Both refactors; the
   records that govern the files get their "unchanged, because" lines.
   **First half done the same day** (DESIGN, "The tier is on the value"): `sv_check::Tier` on `Verified`, set
   where each credit is made; `Inputs` has one list; `sv_report::status_of` with a unit test per tier.
   **Second half done the same day** (DESIGN, "The run's script is in `sv-check`, and runs without Docker"):
   `sv_check::script::run` against the trait `Services`, which `sv-run`'s `DockerRun` implements over Docker;
   `run_after_cleanup` from 568 lines to 430, the fence, the helpers, the app, the install step, the tests, and
   the teardown; the script's own tests show the order against a harness that answers nothing.
5. **A two-page `docs/ARCHITECTURE.md`.** There is no ten-minute map: DESIGN.md is 13,084 lines in 281 dated
   sections and its opening still describes "a second version beside v1 in `agnostic/`"; CLAUDE.md's eight-line
   Layout paragraph is the nearest thing. Lift it from text that exists: the chain listing, scan, resolve, bucket,
   the pipeline's stages, the nine statuses in order (`sv-report/src/lib.rs:44-88`), the five rule mechanisms and
   where a new one goes, the four citation gates, the exit codes, and `data/README.md`. Held to files that exist,
   as `decision_records.rs` holds the records. **Claimed with items 1 to 4 by session securevibe-review.**
   **Done the same day**: `docs/ARCHITECTURE.md` (the crates in the order a run passes through them, the stages
   of `sv report`, the nine statuses, the five kinds of rule and the four citation gates, the exit codes, the MCP
   server, the rules that hold everywhere, and where to look), held to files that exist by
   `crates/sv-cli/tests/architecture_map.rs`; DESIGN.md's opening says it is the dated record and points here;
   CLAUDE.md's layout line names it first.
6. **One answer type for `send`.** The "a crash or a limiter is not an answer" rule exists in seven places with
   three definitions (`signed_in/mod.rs:1282`, `sessions.rs:274`, `fetch.rs:264`, `burst.rs:153`, `once.rs:118`,
   `ai.rs:1932`, `mcp_server.rs:199`, the last missing the 503-with-Retry-After case `rate_limited` knows), and the
   OIDC, MCP, fetch, and AI suites take the raw `DockerHttp` and never wait a limiter out. `Result<ProbeResponse,
   NoAnswer { Silent, Crashed, Limited }>` makes a 5xx body unreadable as a refusal unless a check chooses to.
   Changes what a request's answer counts as: a Later entry on ADR-021. The four suites then gain limiter waits,
   so item 7 goes with it.
   **Claimed 8 October 2026 by session securevibe-review**, with item 7 (branch `claude/securevibe-review-one-answer`).
   **Done the same day** (ADR-021, Later, 8 October 2026; DESIGN, "One rule for what an answer is, and one wait for
   the whole run"): `answer_of`, the seven places through it, `Patient` around the OIDC, MCP, and fetch suites with
   one budget for the run; the AI suite left as it is, with why.
7. **The probe sidecar's life is a fixed 900 s** (`docker.rs:84`), not derived from the request budget: 300 s of
   limiter waiting plus the AI suite's fixed waits can outlive it, after which every request reads as "no answer"
   and nothing names the sidecar. Tie it to the budget and have `probe` tell "container gone" from "app silent".
   A Later entry on ADR-025.
   **Claimed 8 October 2026 by session securevibe-review**, with item 6 (the same branch).
   **Done the same day** (ADR-025, Later, 8 October 2026): `SIDECAR_SECONDS` built from `MOST_WAITING`, and a lost
   sidecar named in the run's output and the report (`RunOutcome::sidecar_lost`).
8. **A check cannot be made to say what it asked.** A check is `fn(.., out: &mut Outcome)` and nothing requires it
   to touch `out`: about 200 hand-written `not_assessed.push` sites, and four early returns with none
   (`sessions.rs:711`, fixed on 8 October; `sessions.rs:298`, `passwords.rs:1318`, `signin.rs:618`). Cheapest: a
   `#[must_use]` guard per rule whose drop records "asked and never answered", plus one test that every rule's ids
   land in exactly one bucket on the correct app and on the all-flaws app. Fuller: checks return a `Verdict`.
   **Claimed 8 October 2026 by session securevibe-review**, the cheaper form first (branch `claude/securevibe-review-asked-and-answered`).
   **The cheaper form done the same day** (DESIGN, "A check says what it asked, in every configuration"): the
   five silent returns and the two lists that named too few, and `asked_tests.rs`, which runs the suite three
   ways and holds every requirement named on the correct app to be named in each; it found V14.3.1 and V3.5.2
   beyond the three the assessment named. The guard per check is not built.
   **The guard per check claimed 8 October 2026 by session securevibe-e9**, from the roadmap (Phase 2, first), in
   branch `claude/securevibe-e9-check-guard`: each signed-in check is called through one wrapper that names the rules
   it speaks to, and when the check returns without naming one of their requirements (no finding, credit, or
   not-assessed entry of its own), the wrapper records it as not assessed, "asked and never answered", and a debug
   build (the test suite) fails there. A silent return is then impossible in a report rather than caught by a test.
   Record, proposed with this claim: ADR-021, Later (a report can now say a check fell silent). Confirmed on `main`
   just before this claim: no such wrapper, and no other session holds this part.
   **Done the same day** (`docs/design/0310-a-check-that-asked-says-what-it-found-8-october-2026.md`; ADR-021,
   Later): measured first, which showed that a check may rightly say nothing when its part of `securevibe.toml` is
   not set, and may name only some of its requirements, so the guard holds what did hold. The 30 checks that speak
   once they have asked go through `asked!`, which records "asked and never answered", and stops sv-check's own tests,
   when one asked and named nothing; the 16 whose silence is their answer go through `quiet!`; a test fails on a check
   called through neither. It found one silent return (`archive_checks`, a gzip-only upload), now fixed.
9. **The stand-in protocol is defined twice**: the JS owns it (`/_sv/health`, `/_sv/mode`, `/_sv/keys/<tag>`,
   `SV-PROBE-<KIND>-<tag>`) and the Rust clients and fakes repeat it as strings; only `model_provider.rs` runs the
   real script. One `stand_in` module of constants shared by clients and fakes, and a contract test for
   `oidc-provider.mjs` as there is for the model. The browser driver has the same split (`browser.rs:139-150`
   against `browser-driver.mjs:262-287`).
   **Claimed 9 October 2026 by session securevibe-e9**, from the roadmap (Phase 2, next after item 8; Phase 1's open
   parts each need Docker, a run against a live site the owner has not agreed to, or a new compressor), in branch
   `claude/stackvet-e9-stand-in`: one `stand_in` module in `sv-check` holding the protocol's paths and markers, used by
   the Rust clients, the Docker runner, and the fakes in place of their own strings; and a contract test that runs the
   real `oidc-provider.mjs` under Node and holds it to those constants, as `model_provider.rs` does for the model's
   script. The browser driver's split goes in the same way if it is as small; otherwise it stays open, and the done
   note says so. Nothing a run asks or concludes changes. Confirmed on `main` just before this claim: the strings are
   still repeated, only the model's script is run by a test, and no other session holds this part.
   **Done the same day, apart from the browser driver** (`docs/design/0317-the-stand-in-protocol-defined-once-9-october-2026.md`):
   `sv_check::stand_in` holds the addresses, the message marker, and the sign-in provider's modes, and the Rust
   clients, the Docker runner, and the fakes take them from there; `crates/sv-run/tests/oidc_provider.rs` runs the real
   sign-in provider under Node and holds every mode to what the Rust side assumes. The browser driver stays open: its
   Rust side is already one function (`Action::to_json`), and running the driver in a test needs a real browser.
10. **The MCP server.** Fold `securevibe_questions` into `securevibe_check {section: "questions"}` and
   `securevibe_notes_file` into `securevibe_record_answer` (fewer ways to do one thing, two fewer full check runs
   per loop; an ADR Later entry, the docs' "thirteen", `image_smoke.py`; the owner's VS Code flow used
   `securevibe_questions` by name). Write the server's own record: no ADR owns it, and its decisions are a module
   doc and five dated DESIGN sections; add `mcp.rs:1375` and `main.rs:5318` to ADR-041's Governs line. Inject the
   check into `Server` so the time-limit test uses a fake that blocks on a channel instead of running the real
   check on `examples/flask-booking` six times, and the `#[cfg(test)] hold` field leaves the production struct.
   One source for the AI-facing flow text: `INSTRUCTIONS`, the tool descriptions, the spec `sv init` prints, and
   GETTING-STARTED's pasted prompt are kept in step by hand and the prompt's order differs; a test that the tool
   names appear in the same order, and a banned-word and American-spelling test over every string the AI tool
   reads (none exists). Reading stdin on its own thread, so `ping` and `notifications/canceled` are answered
   during a check, only if a client is seen to time out (a decision).
11. **Process.** Every session inserts its claim at the top of this file's "Next" section, so a branch an hour old
   conflicts with `main` here; the same conflict was resolved three times on 8 October, each costing a 20-minute
   CI round. Append claims at the end of "Next" instead (a CLAUDE.md line), and merge the claim pull request before
   building rather than carrying it on the build branch. Two "both added here" code conflicts the same day came
   from two sessions appending a test to the same module and a paragraph to the same DESIGN section: new tests in
   sibling `*_tests.rs` files and new DESIGN sections per topic cut that further. Split the tests out of the seven
   modules over 3,000 lines (`ast.rs`, `ai.rs`, `probes.rs`, `adapters.rs`, `secrets.rs`, `production.rs`,
   `sbom.rs`; 40 to 65% of each is tests), then `ast.rs` and `sbom.rs` along their seams.
   **Claimed 8 October 2026 by session securevibe-review**: the CLAUDE.md line, and the tests split out of the seven modules (branch `claude/securevibe-review-tests-apart`).
   **Done the same day** (CLAUDE.md, the claim bullet; DESIGN, "The tests of the seven largest modules live beside
   them"): the rule written down, and the eleven test modules of the seven files moved to `src/<module>/<name>.rs`,
   verbatim. Not done: `ast.rs` and `sbom.rs` along their seams.
12. **Smaller seams in the pipeline.** `Signature.condition` in `sv-scan` is a `String` skipped at run time when
   unknown (`sv-scan/src/lib.rs:297`), where the `Condition` enum refuses unknown names everywhere else: type it
   (ADR-015 governs both data files; one line). `not_for_tests` (`main.rs:4492-4510`) decides an applicability
   class in the CLI with a text heuristic; move it beside `verification_class_for` in `sv-frameworks` (ADR-050).
   `coverage.py` carries a 180-entry Python mirror of Rust string constants with each check's tier asserted in
   Python and never read from Rust; have `Verified::new` log the kind of run so the mirror shrinks to the
   findings-only list. `AstRule` has grown about twenty optional per-language fields with no schema but the
   struct's doc comments: a short schema in `data/README.md`. Send the 28 anonymous probes together
   (`probe_together` exists; about 3 s per run). Then the library move: a crate or module with typed stage structs
   (`StaticScan`, `Advisories`, `RunningApp`, `PersonsWord`, `Reviewed`), `Loaded` and `ReportOptions` typed, and
   `sv-cli` and `mcp.rs` reduced to arguments and printing; after items 3 and 4, so the seams are already cut.
