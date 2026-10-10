# A time on each running-app suite (10 October 2026)

Backlog 226 (the observability review), part 2, item 13's remainder, built by session securevibe-e2. The first part
(`docs/design/0347-how-long-each-part-of-a-run-took-and-what-each-outside-tool.md`) timed the ten stages of
`sv report` and each outside tool. The stage that runs the app, often the longest, was one number: which suite of
questions inside it took the time was not said.

**What was built.** The script (`sv_check::script::run`) keeps when each suite begins, through the same point that
says its name at a terminal (`docs/design/0361-a-progress-line-for-each-outside-tool-and-each-running-app.md`), and
times each from its start to the next one's, the last to the script's end; `script::Outcome::timings`. The Docker run
adds the app's own tests, timed around the test command, and hands both on as `RunOutcome::suite_timings`.
`sv report` lists them in `report.json`'s `timings` after the stages and the tools, each named "the running app, …"
(`sv_report::SUITE_TIMING`), so "The slowest parts" can name one, and the total leaves them out, as it leaves out the
tools: each ran inside the stage that ran the app, whose time already holds it.

Not built: a time on each request inside a suite. Each suite's steps are strings, and a time on each would mean each
suite timing itself; left open on part 13.

**Tests.** `crates/sv-check/src/script/progress_tests.rs` (1 new: every suite timed in order, and time held back
before one suite begins is the previous suite's), `crates/sv-report/src/timing_tests.rs` (2: a suite named among the
slowest and left out of the total; no timings, no line), `crates/sv-cli/src/assemble/timing_tests.rs` (1: suites
listed after the stages, under their name), and `crates/sv-cli/tests/report_suite_timings.rs` (1: the real
`sv report --run` on `examples/tested-notes` behind real containers times the anonymous questions and the app's own
tests; with no backend, no suite is said to be timed, and `SV_REQUIRE_BACKEND=1` makes that absence a failure).

**Broken on purpose, each put back:** each suite's time ending where it began (1 red), the times not kept (1 red),
the suites counted in the total (1 red), and the suites not added to the report (1 red). The Docker run's own part
(the app's tests timed, the times handed on, and `sv report` taking them) is caught only where a container backend is
present, which CI requires and the session that built this did not have; there it was not broken on purpose.
