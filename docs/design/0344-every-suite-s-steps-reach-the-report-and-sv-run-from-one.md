# Every suite's steps reach the report and sv run, from one list (9 October 2026)

Backlog 226 (the observability review), part 1, item 4, built by session stackvet-e9.

**What was wrong.** Each suite of questions beyond the anonymous ones keeps its steps: what it asked and what came
back. The report's list of steps (`run_steps` in `assemble.rs`) and `sv run`'s printout each named the suites one by
one, and both named only three: the signed-in users, the test sign-in provider, and the AI feature. The MCP-server
suite (eight steps) and the fetch suite (two) were left out of both, so their findings and credits arrived and what
was asked to reach them did not. The evidence (`running_app_evidence` in `lib.rs`) had a third list of its own, which
did have all five.

**What changed.** `RunOutcome::asked` (`crates/sv-run/src/lib.rs`) is the one list: each suite asked, in the order it
is asked, with the words `sv run` puts before its steps. The evidence, the report's steps, and the printout all read
it. It names every field of `RunOutcome`, the five suites and the rest marked as not suites, so a sixth suite added
later does not build until it is placed in the list or said not to be one. The first three suites' printout lines
read as before; the two new ones read "Then, its MCP server, asked as an MCP client would: …" and "Then, its feature
that fetches an address, given one it should not go to: …".

**Tests.** `crates/sv-run/src/asked_tests.rs` sets all five suites and checks every step comes back in order, each
with its own lead, and that a suite not asked is not listed. Break: with the MCP-server and fetch suites taken out of
the list, both tests fail.
