# Why and when a caught prompt injection was stopped (9 October 2026)


AISVS C12.1.2 asks that safety filtering and policy decisions are logged in enough detail for audit, debugging and
investigation (ADR-074). The AI checks already look in the app's output for a line recording the textbook prompt
injection they sent as caught (C12.2.1, `probe.ai-injection-logged`). `probe.ai-safety-decision-detailed` reads that
same line, the first that matched, for why and when: a `reason`, `category`, `rule`, `policy`, `score` or `label`
field, in JSON or `key=value`, and a timestamp, as the log checks read one (`logs::has_timestamp`). With both, it is
credited in part, the credit saying whether the line also names the signed-in user (by address or a user field) or a
session; one kind of safety decision, the injection screen, is seen.

It is never a finding: the detail may be recorded elsewhere. A line without a reason or a time says which was not
seen, and no line at all, or an output with nothing in it, is said too. The kill-switch log (C12.4.3) was considered
first and left, since nothing reads the second copy's output yet.

Checked: the AI checks' tests, with a JSON line with a reason, one naming the user by a field, one by address alone, a
plain line with a rule and a session, and lines with no time, no reason, no caught line, and no output. Eight guards
broken one at a time, each caught. One break was first written so it changed nothing (`false && a || b` still lets `b`
through), and naming the user by address alone had no case; both were put right.
