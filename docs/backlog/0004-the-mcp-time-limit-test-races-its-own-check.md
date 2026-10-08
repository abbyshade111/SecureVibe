# The MCP time-limit test races its own check

**Status:** done, as its markers read on 8 October 2026

Found on 8 October 2026 by session securevibe-e9, in a full
`cargo test --workspace` run: `mcp::tests::a_check_that_runs_out_of_time_says_nothing_was_assessed_and_the_server_goes_on`
(`crates/sv-cli/src/mcp.rs`) asserts the check that ran out of time is still running, then calls again and expects
"still finishing". Under load the check ends between the two, and the second call times out instead. It passed 5
of 5 times alone. **Claimed the same day by session securevibe-e9** ("go ahead and fix the test race next"), in
branch `claude/securevibe-e9-mcp-race`: a gate, only in tests, holds the check open until the test lets it go.
**Done the same day:** `Hold` in `mcp.rs`, which the check waits at before it hands back its report. With a
three-second pause put between the two calls, the test passed with the gate and failed without it, as in the full
run.
