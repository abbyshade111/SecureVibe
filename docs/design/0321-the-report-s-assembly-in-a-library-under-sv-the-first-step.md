# The report's assembly in a library under sv, the first step of the library move (9 October 2026)

The first of the short pull requests the library move was claimed as (BACKLOG, "From the architecture assessment of
8 October 2026: the four costs worth paying down", item 12, its last part). `sv-cli` was a binary and nothing else:
the report's assembly, which the MCP server calls as well as `sv report`, lived among the commands in `main.rs` and
read everything there (`use super::*`), so nothing marked where the pipeline ended and the command line began.

**What moved.** `sv-cli` now has a library, `crates/sv-cli/src/lib.rs`, and `sv` is built on it. In the library: the
stages of a run (`static_scan`, `assemble`), what they read (`Loaded`, `ReportOptions`), the functions they call
(the running app's questions and evidence, the gaps for dependencies, folders set apart, rate limiters and a lost
sidecar, the decisions and reviews, the data paths), and the modules those need (`exit`, `report_lock`, and
`bundle`, which the lock uses for its time and hash). What went was found by building the library and moving what it
could not find, until it built: 28 functions, three structs with their `impl`s, and five modules, about 820 lines
of `main.rs`, none of them changed apart from `pub` on
what the binary calls. The binary keeps the commands, `report_folder`, the seal, the review, and the MCP server, and
reads the library's items with one `use sv_cli::*`, so `crate::Loaded` and the rest still resolve where the binary's
modules used them.

**The stage results are named and public.** `StaticScan` was already; `Advisories`, `Tools`, `RunningApp` (was `Run`),
`PersonsWord` (was `OwnersWord`), and `Gathered` are now public with public fields, under the names the assessment
gave, so a later step can hand them across the boundary.

**One test moved.** `every_fail_on_the_ai_tool_is_told_to_use_is_one_sv_takes` was in `exit.rs`'s tests and read the
MCP server's instructions, which stay in the binary; it is now `crates/sv-cli/src/fail_on_tests.rs`, unchanged.

**Nothing a command prints or writes changed.** The witness is every `sv-cli` test, the verdict snapshots
(`crates/sv-cli/tests/verdicts.rs`) among them, which run the `sv` binary: all pass, with Docker. `tools/coverage.py`
regenerates `docs/COVERAGE.md`, `docs/REQUIREMENTS.md`, and `data/reach.json` unchanged. That the tests do read the
moved code: `not_the_app_gaps`, now the library's, made to return nothing failed five of them.

What remains of the move, as claimed: the plan, the brief, and the preflight the same way, so `main.rs` is the
arguments and the printing; then the MCP server's tools calling the library and nothing of the command line.
