# The plan, the brief, and the preflight in the library, the library move's second step (9 October 2026)

The second of the short pull requests the library move was claimed as (BACKLOG, "From the architecture assessment of
8 October 2026: the four costs worth paying down", item 12, its last part), after the first put the report's assembly
in a library under `sv` (design entry "The report's assembly in a library under sv").

**What moved.** The plan (`plan.rs`, `plan_for`, `plan_options`), the brief before a feature (`brief.rs`, `brief_for`,
`brief_without_manifest`, `feature_briefs_path`), the preflight (`preflight.rs`), and the answer in parts that the plan
and the check share (`parts.rs`) are the library's now, with the three functions they reach for the prompt library
(`design_prompts`, `coding_prompts`, `prompts_paths`). Found as before: the library was told to take these and built
until it found nothing missing. Nothing in them changed apart from `pub(crate)` becoming `pub` where the binary calls
them. `cmd_plan`, `cmd_brief`, and `cmd_preflight`, which read the arguments and print, stay in `main.rs`, as does the
MCP server, which calls the same library functions as before through `use sv_cli::*`.

**Nothing a command prints or writes changed.** Every `sv-cli` test passes with Docker, the verdict snapshots and the
plan's, the brief's, and the preflight's own among them, and `tools/coverage.py` regenerates its three files
unchanged.

What remains, as claimed: the MCP server's tools calling the library and nothing of the command line.
