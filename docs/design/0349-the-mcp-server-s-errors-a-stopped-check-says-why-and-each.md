# The MCP server's errors: a stopped check says why, and each error leaves a line on stderr (10 October 2026)

Backlog 226 (the observability review), part 2: item 19, and the rest of item 16. Built by session stackvet-e9.

**A check that stopped (item 16).** When the check's thread ended without sending its report, the tool said only "the
check stopped before it finished, so nothing was assessed". Only a panic ends the thread that way: a fault in `sv`,
not in the app. The tool now joins the thread, takes what the panic said, and says that cause. It also says the
result is not a pass and not a failure, and gives the command that runs the same check at a terminal, where the
whole error shows. The next step is `sv`'s own, outside the fence: ask the person to run that command and pass
what it says to whoever looks after `sv`. The panic's words are inside the fence, with the rest of the problem.

**A record of each error (item 19).** The MCP server kept no record of an error it returned. `serve` now writes one
line on stderr for each, which the AI coding tool's own log of the server usually keeps. The line comes from
`error_line` in `crates/sv-cli/src/mcp/protocol.rs`:

- `sv mcp: <tool> answered with an error: it could not do this[, and said what to do]` for a tool result marked
  `isError`;
- `sv mcp: <method> was answered with protocol error <code> (<kind>)` for a protocol error.

No words of the app's are in it. A tool's or method's name is kept only when it is a plain name (lower case, `_`
and `/`, at most 64 bytes); anything else is "a tool" or "a request". What the error says stays in the answer. Only
an answer that could be an error is parsed, so a large report costs nothing extra.

**Tests.** `a_check_that_stops_on_a_fault_says_why_and_where_to_see_the_whole_error` swaps in a check that panics.
`an_error_answer_leaves_one_line_naming_the_tool_and_the_kind_and_no_app_text` covers `error_line`.
`each_error_answer_leaves_a_line_on_stderr_and_no_app_text` in `tests/mcp_stdio.rs` reads the real binary's stderr.
With its fix undone, each fails.
