# A tool that does not answer, and C9.1.1 checked in part (8 October 2026)


C9.1.1 asks that per-tool quotas and timeouts (CPU, memory, disk, egress and execution time) are enforced. Of those,
only execution time can be seen from outside the app, so that is what is asked (ADR-064). The test model's `MCPHANG`
kind asks for the test MCP server's `sv_lookup`, as `MCPPLAIN` does, and the MCP server takes that call and answers
nothing for `HANG_SECONDS` (40 in a run), then closes it, as the held AI message is held for V16.5.2. What was seen
for the tag says the call arrived (`mcp_called`) and, once the hold is over, that it was let go (`mcp_released`).

The AI check asks it last of the MCP questions, after the control showed the tool called and its result reaching the
model, so a call that never arrives is the app's doing. `probe.ai-tool-timeout` is credited, marked in part, when the
app answered the message by itself within the 15 seconds `sv` waits on any request, while the call had arrived and
had not been let go, and its answer carried no trace. The credit says it is execution time only, for one tool, and a
line under C9.1.1 says the other four are not seen. It is never a finding: no answer within 15 seconds cannot be told
from a limit longer than that, an answer carrying a trace is V16.5.1's question, and one that came only after the
tool let go shows the tool's limit, not the app's; each is said instead. When the app may still be waiting on the
tool, the hold is waited out before the checks after it. Not asked where the app offers no MCP tool or the control
failed, and said so.

`tools/coverage.py` gained `RUST_IN_PART`, checks whose credit is only ever in part, so `docs/REQUIREMENTS.md` says
"only ever in part" beside this one and `docs/COVERAGE.md` says C9.1.1 is checked in part only, not settled.

Checked: the AI checks' tests, with a fake app that answers in time, waits on the tool, answers with a traceback,
answers only after the tool let go, offers no tool, never calls it, or calls it only once; six guards broken one at a
time and each caught. The stand-in service's own test under Node, with the hold, the release and an unheld control;
three breaks of the hold, each caught. Not run end to end against an app under `sv run`, which needs Docker.
