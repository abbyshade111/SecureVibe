# A tool action the AI took, written down with its argument (9 October 2026)


AISVS C12.4.2 asks that audit logs capture security-critical proactive actions with the approver, the time, the
action's parameters and the outcome (ADR-075). When the app gives its model tools from an MCP server, the MCP checks'
control question has the test model ask for the test tool `sv_lookup` with the message's tag as its argument. When
that call reaches the test MCP server, the tag is kept (`LogMarkers.tool_call`), and after the run the app's output is
read for a line naming `sv_lookup` and carrying the tag outside the person's message as it was logged
(`SV-PROBE-MCPPLAIN-` and the tag), which records the message, not the action.

`probe.ai-tool-action-logged` is credited in part when there is such a line, saying whether it also has a time; the
action is a read-only lookup, not a security-critical one, and no approver or outcome is seen. It is never a finding.
No such line, an output with nothing in it, and a control call that never reached the tool are each said.

Checked: the AI checks' tests, with the call logged with a time, as JSON without one, the tag only inside the logged
message, the tool without the tag, the tool's answer without the tool's name, nothing at all, and an app that never
calls the tool. Eight guards broken one at a time, each caught. The rule that the line must name the tool was caught
only once a line recording just the tool's answer was added, since that answer carries the tag too.
