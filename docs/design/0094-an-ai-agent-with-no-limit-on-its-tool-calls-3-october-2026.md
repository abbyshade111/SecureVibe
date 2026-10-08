# An AI agent with no limit on its tool calls (3 October 2026)

C9.1.2 asks that each run of an agent has a budget the app enforces: how deep it may go, how many tokens it may
use, how much it may spend. The test model's `MCPLOOP` kind asks for the test MCP server's `sv_lookup` again after
every result, and stops by itself only at 40 rounds (`LOOP_CAP`, the same number in `model-provider.mjs` and
`ai.rs`), so no run can loop for ever. It reports how many results the app sent back before it stopped asking.

The AI check asks it only after the ordinary MCP question showed the tool working, so a round count that stops
early is the app's doing and not a tool that never answered. `probe.ai-agent-unbounded` is a finding when only the
test model's own stop ended the loop, and credited when the app stopped sooner and answered; the credit says it is
a limit on tool rounds, not one shown for tokens or spending. An app that answered with an error part-way is not
assessed: a crash is not a budget. Not done: the same question for an app's own tools named in `record-tool`,
which may not be read-only in every app, and C9.1.1's per-tool quotas and timeouts.
