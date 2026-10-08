# A time limit on a check over MCP (3 October 2026)

A check over MCP had no end. Of a very large folder it could run for as long as the folder took, and the AI tool
waited with nothing to say (BACKLOG, "Hardening the MCP server", item 6, its second half). Each of the four tools
that check the app (`securevibe_check`, `securevibe_questions`, `securevibe_write_report`, and `securevibe_bundle`)
now waits at most 50 seconds. If the check has not finished by then, the tool is told it did not finish, that nothing
was assessed (not a pass and not a failure), and how the person can run it at a terminal, where `sv report` has no
limit, or that it can check a smaller folder.

**Why 50 seconds.** Checking this whole repository takes about six seconds, and an app takes a fraction of that.
A client commonly gives up on a request after a minute (the official TypeScript SDK's default), and an answer it has
stopped waiting for tells the person nothing, so the limit is under a minute. `sv mcp --time-limit SECONDS` changes
it for a person whose apps need longer; a limit of 0, or one that is not a whole number, is refused.

**What happens to a check that ran out of time.** The check runs on a thread of its own, and a thread cannot be
stopped from outside, so it runs on to its end and its result is dropped. Until it ends, a new check is refused
rather than started beside it, saying why, so checks that run out of time cannot pile up and take all the computer
has. The frameworks and rules are shared with it rather than loaded again.

**Not done here.** `securevibe_write_report` makes its folder before it checks the app, so a check that runs out of
time can leave that folder there, empty. The check is not made any faster, and the tool is not told how far it got;
progress notifications are item 4 of "Improving the MCP server".

Two tests: every one of the four tools, given a limit too short to finish, says that nothing was assessed, refuses a
second check while the first is still running (the test makes sure it is), and finishes as before once the first has
ended; and the limit given at the command line is refused when it is 0, negative, not a number, a fraction, or
missing. Seven ways broken, each caught: no limit, a second check started beside the first, the running check not
kept, a limit of 0 allowed, a result that does not say nothing was assessed, one tool that skips the limit, and a
check that finished in time not waited out to its end.

**Found on the way.** The first version refused a check that came right after one that had finished in time: the
finished check had sent its result, but its thread had not quite ended, so it looked still running. The whole test
suite, run under load, found it once, in a test that calls each tool in turn. A check that finishes in time is now
waited out to its end, which takes no time, and the test makes sure no finished check is still held.
