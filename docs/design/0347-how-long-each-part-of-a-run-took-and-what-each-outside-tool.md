# How long each part of a run took, and what each outside tool was (10 October 2026)

Backlog 226 (the observability review), part 2, items 13 and 14, built by session stackvet-e9.

**What each outside tool was (item 14).** `sv` asked each tool its version to learn whether it worked, then threw the
answer away; nothing kept which program ran, with what arguments, how it ended, or how long it took. A tool's run is
now written down in a `ToolRun` (`crates/sv-check/src/adapters.rs`): the program that ran (the adapter's own, or the
stand-in in its place), the first line it answered to its version question, the adapter's arguments with `{dir}` and
the like left unfilled so no path of the person's computer is kept, its exit code when it ran to the end, and the
milliseconds from the version question to the report read. The version question now pipes stdout, which is where
tools print their version, and `finish_unless` reads it the way it reads stderr; the line is redacted and cut as
anything a tool says is. `AdapterRun::tools` carries the records, and each tool's `Examined` entry in `report.json`
gains `tool`. Keeping a tool's raw output stays part 3, item A, the owner's.

**How long each part took (item 13).** The ten stages `sv report` announces (part 2, item 15) are now timed: each
lasts from its start to the next one's, the last to the report being put together. `report.json` gains `timings`,
the stages in order and then each outside tool, and `report.html` and `compliance.md` say "This run took … s. The
slowest parts: …", naming five. The total counts the stages only, since a tool runs inside its stage.

Not built: a time on each step inside the running-app suites, which are strings today; the suites would need to
time themselves. Left open on part 13.

**Tests.** `crates/sv-check/src/adapters/tool_run_tests.rs`: a fake tool that prints its version on stdout and exits
1 after writing its report; its version line, its unfilled arguments, its exit code, and its time are kept. Without
stdout piped to the version question, it fails. `crates/sv-cli/tests/report_timings.rs`: the ten stages timed in
order in `report.json`, and the slowest named on both pages; with the timings left out, it fails.
