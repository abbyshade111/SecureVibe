# An AI agent's limit, asked through the app's own read-only tool (7 October 2026)

The C9.1.2 loop question (DESIGN, "An AI agent with no limit on its tool calls") had the test model ask for the test
MCP server's `sv_lookup` again after every result. So it reached only apps that take tools from an MCP server. An app
whose model calls the app's own tools was never asked.

The owner decided on 6 October 2026 that the app's own tools may be used, but only when `securevibe.toml` marks them
read-only, since a tool called forty times may write forty times (ADR-045, which records that decision):

- **`read-only = true` on `[stack.run.ai] record-tool`.** Without it, the tool is never called in a loop, and a step
  of the run says why. The spec `sv init` prints says what the setting does.
- **A new test-model kind, `FETCHLOOP`.** Like `FETCH`, it asks for the tool the message names. Then it asks again
  after every result, up to the same 40 rounds as `MCPLOOP`, counting the results the app sent back.
- **Asked inside the record-tool question,** once the tool has handed the second user their own record. That shows
  the tool works, so rounds that stop early are the app's doing. It is asked with that user's own record.
- **Judged exactly as the MCP loop is**, by the same function (`judge_tool_loop`):
  - a finding when only the test model's cap ended it;
  - credit when the app stopped sooner, answered without an error, and the count held when read again;
  - not assessed otherwise.

  The step and the finding name the tool.

The mark is the owner's word that the tool only reads. It decides whether the tool is called; it is not evidence of
anything.

Shown with the fake app (a tool stopped at five rounds, one run without a limit, one stopping on an error it caught,
one not marked), and with the real test model under Node, whose loop counts every round and stops itself at 40.

Broken on purpose 6 ways, each caught:
- the read-only gate always open;
- the read-only gate always shut;
- the loop sent as an ordinary `FETCH`;
- the tool not named in the step;
- the test model's loop stopping after one round;
- the rounds not counted.

Not done: C9.1.1's per-tool quotas and timeouts.
