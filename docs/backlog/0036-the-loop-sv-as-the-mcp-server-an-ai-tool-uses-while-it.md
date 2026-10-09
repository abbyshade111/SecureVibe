# The loop: `sv` as the MCP server an AI tool uses while it builds

**Status:** done, 6 October 2026

Proposed on 5 October 2026 by session
paper-facts, after the third prompts trial (`docs/prompts/trial-3/README.md`), where the MCP server's instructions
with the command line gave the most consistently testable builds. **The owner's decision, 5 October 2026: all six,
yes, and the trials' cost approved when each comes to be run.** Each numbered item can be claimed on its own.
1. **Clear the trial's confounds first.** Say in the spec when `seed` runs (the item below); correct the trials'
   brief; and write the protocol of the next trial before it runs: the arms, the measures, the rule, and what makes
   a build unusable (could not start, could not sign in, a check that needs `--slow` not given it). The third
   trial's scoring changed twice after results were seen, each time for a stated reason; deciding it first is the
   cleaner method.
2. **The real loop, a pilot.** Each build in a fresh folder by a headless AI coding tool (`claude -p`, with
   `sv mcp` attached for that run only by `--mcp-config`, so no settings change), with no instruction to use `sv`
   beyond what the server itself says. Its transcript (`--output-format stream-json`) records every tool call. About
   four builds, to prove the setup before spending more. Other tools with MCP (Codex CLI, Gemini CLI, Cursor's agent)
   where the owner has them.
   **Claimed on 5 October 2026 by session paper-facts**, with item 4, at the owner's word, in branch
   `claude/loop-pilot`. Builder: the Claude Code program the desktop app carries (2.1.286), headless, with
   `--restricted`, `--strict-mcp-config`, `--no-session-persistence`, and `--max-budget-usd` on each build; the shell
   allowed only for `python3`, which is not confined to the build's folder, and said so with the results.
3. **Which part of the loop does the work.** Arms: the server's instructions with no `sv`; `sv check` with no
   instructions; the plan only; the whole loop.
4. **The loop's own measures,** from the transcripts: whether the brief and plan came before any code, how many
   check-and-fix rounds, the findings after each round and whether they fell or were argued with, and the time and
   tokens a loop costs.
5. **`securevibe_preflight`: the run settings checked against the code, without running it.** Most testability
   failures in the third trial were sign-ins `sv` could not make: a seed that ignores the `SV_` accounts, a sign-in
   path not where the settings say, tables made only by the seed. A static check of those, offered in the loop,
   executes nothing, keeping the MCP server's rule that a model never starts the app.
6. **Scale.** About five builds a cell, the second brief (`docs/prompts/trial-2`), and security outcomes (the
   running-app findings) as well as testability; other vendors' tools where available.
**Item 1 claimed on 5 October 2026 by session paper-facts**, at the owner's word, in branch `claude/loop-confounds`.
**Item 1 done the same day** (DESIGN, "When the seed runs, said"): the spec and the plan say the seed runs after
the app answers on `health`, in each copy `sv` starts, so the app makes its own tables; a test holds that sentence to
the order in `sv-run`. The trials' brief is corrected, with a note that the first three trials used the old
sentence. The next trials' protocol is `docs/prompts/loop-protocol.md`: the arms, the measures, what makes a build
unusable, what may be said, and the cost guard, fixed before any build.
**Items 2 and 4 done the same day** (DESIGN, "The loop, a pilot"; `docs/prompts/loop-pilot/README.md`): six
loop-arm builds, Sonnet 5.5 and Haiku 4.5, $1.86 of the owner's API credit. Every build used `sv` before any code
without being asked; Haiku stopped to ask the owner until the request said the owner was away (protocol amendment
1); all four builds that wrote an app could be started and signed in to (34, 38, 21, 27 checks answered). Only three
ran `sv check`, each once: no check-and-fix round was seen. The measures are `loop_measures.py`.
**Items 3, 5, and 6 claimed on 5 October 2026 by session paper-facts**, at the owner's word: 3 in branch
`claude/loop-arms`, run on the pilot's `sv` (`87404c8e`) so its loop arm is comparable with the pilot; 5 in branch
`claude/loop-preflight`, with its decision record; 6 after 3, at a size the owner chooses from 3's cost. Each run's
number of builds and estimate goes to the owner before it starts.
Item 5's record is written with its claim, as `proposed`: `docs/adr/ADR-035.md`.
**Item 5 done the same day** (ADR-035; DESIGN, "A preflight of the run settings"): `sv preflight` and
`securevibe_preflight` read the code against `[stack.run]` with nothing run, and say for the start command, the
address and port, the seed's file and `SV_` accounts, where the tables are made, and every path and sign-in field
whether it looks right, needs a look, or could not be told. The server's instructions offer it once the code is
written, before the check. Not yet tried in a loop build: item 3 runs on the pilot's `sv`, which does not have it.
**Item 3 done the same day** (DESIGN, "Which part of the loop does the work"; `docs/prompts/loop-arms/README.md`):
eighteen builds, $4.78. No build without the server wrote a manifest `sv` could read, so none of the eight could be
tested; with the server every build read the specification first, and ten of twelve could be signed in to. The
arms' own tools were mostly unused (the plan called by three of eight builds offered it, all Haiku; the check by
three of eight, once each), so the trial cannot say which of them does the work: what the testable builds share is
the specification.
**Item 6 done on 6 October 2026** (DESIGN, "The loop at scale"; `docs/prompts/loop-scale/README.md`): seventy
builds, $21.34, with the specification in every request (protocol amendment 3) and the check and plan arms also run
with the other tools hidden (amendment 4). Every Sonnet build could be tested, in every arm; Haiku varied within
every arm, and on testability no arm is above another by the protocol's rule. The loop arm checked, fixed, and checked again
(every build checked; all five Haiku and two Sonnet again after a fix), and fixed what the check named: the
committable `.env` in five loop builds, against 56 of 59 builds in the other arms that kept it.
**Later, 6 October 2026, at the owner's asking** (`loop-scale/README.md`, "Findings by group"): counted by group,
the loop arm's builds had fewer findings in their code than every build of five of the six other arms, for both
models, the first difference by the protocol's rule; the running apps' findings were the same in every arm.
