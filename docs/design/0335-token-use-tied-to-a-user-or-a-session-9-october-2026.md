# Token use tied to a user or a session (9 October 2026)


AISVS C12.2.5 asks that token use is tracked per user, per session, per feature endpoint, and per team or workspace
(ADR-073). The AI checks find the line the app wrote for one model call by the token counts the test model reported
for it, which are random every time, and already judge it for C12.1.3 and C12.1.1. `probe.ai-token-use-attributed`
reads the same line for whose call it was. The signed-in test user named, or a `user`, `user_id` or `userid` field,
ties the counts per user; a `session`, `session_id`, `sessionid`, `conversation_id` or `conversationid` field ties them
per session. Either is credited in part, the credit saying which, since per feature endpoint and per team or workspace
are not seen.

It is never a finding, since the counts may be attributed in another record. When the AI feature was asked without
signing in, when no line carried the counts, when the app wrote nothing at all, and when the line names no user and no
session, that is said instead.

Checked: the AI checks' tests, with a line naming the user, a session field, both, neither, an anonymous run, no line
with the counts, and an empty output. Seven guards broken one at a time, each caught; one break first written so it did
not compile, which the break script reports as such rather than as caught, and was rewritten.
