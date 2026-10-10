# The build-loop record says how each call ended and who called (10 October 2026)


Backlog 0231: ADR-084's decisions 1, 2, and 4, item D of the observability review's part 3 (backlog 0226). Built by
session securevibe-e2.

**The problem.** The record of the build loop (ADR-076) could not tell a check that failed or ran out of time from one
that answered, kept no trace of a call to a tool `sv` does not have, said nothing when it was turned off and on again,
lost a call it could not write without a word, and did not say which AI coding tool or which `sv` was used.

**What was built.** `build_loop::Line` gains `outcome`, `client`, `sv`, and `off`. The server learns the AI tool's name
from `initialize` (`build_loop::client_name` keeps it short and plain), sets `ok` or `failed` from the tool's result,
and the check sets `timed-out` or `crashed` when it gives no answer (`tools.rs`, `ended_as`). A tool `sv` does not have
is written down as `unknown`, `refused`. Turned off, one `{"time", "off": true}` line is written, once until a call is
written again (`noted_off`). A write that fails is counted in the process (`build_loop::unwritten`) and the next report
it writes says so. `summarize` counts each outcome, the off lines, and the distinct tools and `sv` versions, and the
report's paragraph says them (`sv_report::build_loop_line`, `loop_gaps`). Every new report field is left out when empty.

**Found on the way.** A branch for an answer marked as an error was written and taken out again: every tool says it
could not do its job as an error, never as an answer so marked, so the branch never ran, and breaking it turned no test
red. The outcome is now `ok` for an answer and `failed` for an error, and breaking that is caught.

**Tests.** `crates/sv-cli/src/build_loop/outcome_tests.rs` (4: the tool's name kept short and plain; each new field
read back and an unknown outcome refused; a summary counting each outcome, the gaps, and the tools; a call that could
not be written counted, on Unix, through a link where the record goes) and
`crates/sv-cli/src/mcp/build_loop_outcome_tests.rs` (3, through the server: a call that answered, one that failed, and
one to a tool `sv` does not have, with the AI tool's name and `sv`'s version, and the report saying them; a check that
ran out of time; the record turned off for three checks and on again, one line for the gap, and the report saying it).
`turned_off_the_report_says_it_cannot_tell` now holds the off line: one line, the time and nothing else.

**Broken on purpose, each put back:** every outcome `ok` (1 red), a time-out not told (1 red), an unknown tool not
written down (1 red), the AI tool's own name for it kept (1 red), the AI tool's name not kept (1 red) and not cleaned
(1 red), an off line for every call (2 red), no off line (2 red), a failed write not counted (1 red), an unknown outcome
read (1 red), and the gap not said (1 red).

**Left for later in ADR-084:** decisions 3 (the names `sv` defines that a call asked for), 5 (what was handed over),
and 6 (the findings' fingerprints at each check), in a pull request of their own.
