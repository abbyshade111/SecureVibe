# The prompts trial, a third time (5 October 2026)

Item 7 of "Design-time help before any code", at the owner's chosen size: Claude Sonnet 5.5 and Claude Haiku 4.5, two
builds per arm, every build checked with `sv report --run` (`docs/prompts/trial-3/README.md` has the method, the
tables, and the files). Part 1 repeated the first trial's prompt arms on its brief, for prompts 1, 3, 4, 6, and 7;
prompt 2 was left out while `probe.action-done-twice` miscounts a correct booking. Part 2 asked whether the help
before any code makes an app `sv run` can test, on a plainer brief with no hint of what a tester needs: the
specification alone, the plan, and the MCP server's instructions with the command line in place of the tools.

**Results.** With Sonnet, prompts 3, 6, and 7 held on every check they were shown on, and 6 on V16.3.2 as well; with
Haiku, 6 and 7 held and 3 did not. Prompts 1 and 4 made no difference with either model. In Part 2, the plan brought
both Sonnet builds to the same high count of running-app checks answered (32 and 31), where the builds without it
gave 9 and 30; with Haiku, `sv` could not sign in to either plan build. The MCP instructions and command line gave
two testable Haiku builds (26 and 26). Two builds a cell is enough to see, not to generalize.

**What the trial got wrong, and how each was found.** Each came from reading what `sv` said, not from guessing:
- every first run reported its app's folder empty inside the container, because Colima shares only the home folder,
  and the trial ran from `/tmp`. Moved, and run again;
- three Haiku builds could not start: the first brief says the seed runs before the app, and `sv` runs it after. A
  local start and a Docker start under the same limits both worked; reading `sv-run` showed when the seed runs. They
  were rebuilt with the sentence corrected, and the gap in the specification is in the backlog;
- prompt 7's session checks need `--slow`, which the builds without a prompt had not been given. They were run again
  with it before prompt 7 was scored;
- a build `sv` could not sign in to was first scored as the prompt failing. It is now left out, as one that did not
  start is, since it says nothing about checks that need a signed-in user.
