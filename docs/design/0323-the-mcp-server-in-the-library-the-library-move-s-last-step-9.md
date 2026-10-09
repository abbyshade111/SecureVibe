# The MCP server in the library, the library move's last step (9 October 2026)

The third and last of the short pull requests the library move was claimed as (BACKLOG, "From the architecture
assessment of 8 October 2026: the four costs worth paying down", item 12, its last part), after the report's assembly
(design entry "The report's assembly in a library under sv") and the plan, the brief, and the preflight (design entry
"The plan, the brief, and the preflight in the library").

**What moved.** What the MCP server still took from the binary: the report folder and its seal (`report_folder.rs`,
`report_seal.rs`, `report_files.rs`, and `claim_report_folder`, `write_report`, `write_report_files`, `refuse_link`, and
the rest of what writing a report folder needs), the notes file and a recorded answer (`write_notes_file`,
`record_tool_answer`, `write_notes`, `notes_facts`), the bundle's writing (`write_bundle`), the prompts and coding rules
for an app (`prompts_at_start`, `prompts_for`, `prompts_for_report`, `whole_app_prompts`, `coding_rules_for`),
`Remedy`, and `assemble_report`. Then the MCP server itself (`mcp/`). Found as before, and changed only where the
binary calls them (`pub`). The re-export of `REPORT_STAGES` and `assemble_report_saying` is the library's now.

**The rule is held by the compiler.** The MCP server is a module of the library, and a library cannot see the binary
built on it, so a tool that reached for anything of the command line would not build. Tried: a function in
`mcp/tools.rs` naming `crate::cmd_check` failed to compile, "cannot find value `cmd_check` in the crate root".

**One test went home.** `every_fail_on_the_ai_tool_is_told_to_use_is_one_sv_takes`, moved out of `exit.rs` in the first
step because it reads the MCP server's instructions, is back in `exit.rs`'s tests as it was, since both are now the
library's; `exit.rs` is the same as before the move began.

**Nothing a command prints or writes changed.** Every `sv-cli` test passes with Docker, and `tools/coverage.py`
regenerates its three files unchanged. `main.rs` is 3,180 lines, from 5,039 before the move: the arguments, the
commands, and the printing, with the larger commands' own logic (`cmd_check`, `cmd_scope`, `cmd_run`) still in them.
Taking that logic out too would change how those commands are written, not where they live, and is not part of this
item.
