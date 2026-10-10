# A progress line for each outside tool and each running-app suite (10 October 2026)

Backlog 226 (the observability review), part 2, item 15's remainder, built by session securevibe-e2. The first part
gave `sv report` a line on stderr as each of its ten stages begins (`stage_line`). The two longest stages, the
outside tools and the running app, still printed one line each and were then silent for minutes.

**What was built.** Within those two stages, a line on stderr as each piece begins, indented under its stage:

```
sv report: 8 of 10, Running the outside tools, when asked with --tools
  now: Bandit
  now: Semgrep
  now: CodeQL (Python)
sv report: 9 of 10, Running the app, when asked with --run
  now: the questions asked as somebody not signed in
  now: the questions asked as the test users
  now: the app's own tests
```

- The outside tools: `sv_check::adapters::run_all_in` takes `starting`, told each tool's name as `sv` begins on it,
  before it looks for the program, so a tool that is not installed is named and then said not to have run.
- The running app: the script's harness (`sv_check::script::Services`) has `starting`, nothing by default, told the
  name of each suite the manifest asks for as it begins; a suite not asked for says nothing. The Docker harness passes
  it to `RunPlan::on_step` (an `OnStep`, which any other compares equal to: how a run is watched is not what it
  runs), and says "the app's own tests" before the declared test command.
- Both reach the terminal only: `sv run` and `sv report --run --tools` set them (`assemble::say_step`, through
  `step_line`). The MCP server starts neither the app nor the tools, so it is unchanged. The report on stdout is left
  alone.

**Tests.** `crates/sv-check/src/script/progress_tests.rs` (2: each suite's name before its requests, in order; only
the anonymous questions when the manifest asks for nothing else), `crates/sv-check/src/adapters/progress_tests.rs`
(1: two stand-in tools named in order, both really run), `crates/sv-cli/tests/report_progress_steps.rs` (1: the
real `sv report --tools`, the three Python tools named between stages 8 and 9, nothing on stdout), and
`crates/sv-cli/tests/run_progress.rs` (1: the real `sv run` on `examples/tested-notes` behind real containers says the
anonymous questions and then the app's own tests; with no backend, nothing is said to begin, and
`SV_REQUIRE_BACKEND=1` makes that absence a failure).

**Broken on purpose, each put back:** no name from the tools' loop (2 red), the terminal's `say_step` replaced by
nothing (1 red), the AI suite's line left out (1 red), the anonymous questions' line left out (2 red). The Docker
harness's own lines (`DockerRun::starting`, the line before the app's tests, and `sv run` setting `on_step`) are
caught by `run_progress.rs` only where a container backend is present, which CI requires and the session that built
this did not have; there they were not broken on purpose.
