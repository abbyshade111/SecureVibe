# Which part of the loop does the work (5 October 2026)

Item 3 of the backlog's "The loop: `sv` as the MCP server an AI tool uses while it builds", run to
`docs/prompts/loop-protocol.md` with both amendments: the five arms, Claude Sonnet 5.5 and Claude Haiku 4.5, two
builds a cell. Each build is a headless Claude Code (2.1.286) in a fresh folder, given the plain brief
(`docs/prompts/trial-3/plain-brief.md`) with the sentence saying the owner is away, and checked with
`sv report --run`. `sv` was the pilot's release build (`87404c8e`) throughout, so the loop arm here and the pilot's can
be read together; it does not have `securevibe_preflight`.

Eighteen new builds, $4.78 of the owner's API credit. The Haiku loop cell is the pilot's two amended builds (Haiku 3
and 4, `docs/prompts/loop-pilot/`), made the same way. Two builds a cell: this says what was seen, and the protocol
allows "a difference" only where every build in one arm is above every build in the other.

## What was seen

Running-app checks answered (`answered` in `loop-measures.json`), each build:

| Arm | What the builder had | Sonnet 5.5 | Haiku 4.5 |
|---|---|---|---|
| none | no `sv` | 0, 0 | 0, 0 |
| instructions | the server's instructions in the request, no server | 0, 0 | 0, 0 |
| check | the server, allowed `securevibe_spec` and `securevibe_check` | 33, 9 | 27, 0 |
| plan | the server, allowed `securevibe_spec` and `securevibe_plan` | 26, 24 | 23, 26 |
| loop | the server, every tool | 32, 7 | 21, 27 |

1. **No build without the server wrote a `securevibe.toml` `sv` could read,** so none of the eight could be tested at
   all. The plain brief says the owner checks apps with `sv`; two of the four without it wrote no manifest, and two
   guessed at its format (`command = ...`). All four given the server's instructions but not the server wrote one,
   each with fields `sv` does not have, because the instructions say to get the format from `securevibe_spec`, which
   they did not have. By the protocol's rule this is a difference for both models: every plan and loop build is above
   every build in these two arms, and every Sonnet check build.
2. **With the server, every build read the specification first,** before any code, in every arm (`spec_before_code`).
   Eleven of the twelve wrote a manifest `sv` could read, and all eleven started; ten could be signed in to.
3. **The tool each arm exists to test was mostly not used.** `securevibe_plan` was offered to eight builds (plan and
   loop arms) and called by three, all Haiku; no Sonnet build asked for the plan. `securevibe_check` was offered to
   eight (check and loop arms) and called by three, once each, near the end; no build checked, fixed, and checked
   again. So between the check, plan, and loop arms this trial cannot say which part does the work: what they share,
   and what the arms without the server lack, is the specification.
4. **Between the arms with the server, no difference** by the rule, for either model.
5. **Tools refused by the arm's limits were asked for anyway:** every check and plan build asked for
   `securevibe_guidance`, which the instructions name, and was refused; one Haiku check build made six refused
   calls. The arms limited what the builder could use, not what it was told about.

**Later, 6 October 2026.** The check and plan arms here listed every tool and refused the ones they leave out. Item
6 found that refused builders give up on SecureVibe's tools altogether, the allowed ones included, and that with the
others hidden the check and the plan are asked for far more often (`loop-scale/README.md`, protocol amendment 4). So
point 3 above is in part a result of how the arms were limited, not only of what the builders chose.

## Why the low builds are low

- **Sonnet check 2 (9):** the app's own limit on sign-in attempts answered the admin's sign-in with 429, so `sv` could
  not show both users signed in and most signed-in checks had nothing to work with. Trial 3's lowest Sonnet build
  failed the same way.
- **Sonnet loop 4 (7):** signing in as the first test user did not open `/account`. The cause was not found in the time
  given: the settings, the paths, and the form fields all match the code, and the preflight (item 5) finds nothing to
  look at.
- **Haiku check 2 (0):** its `securevibe.toml` does not parse (an `ai` entry with a field, `form`, that `sv` does not
  have), so `sv` could not read it.

## Cost and time

Per build: Sonnet $0.14 to $0.37 and one to two and a half minutes; Haiku $0.12 to $0.55 and two to five and a half
minutes. The arms without the server were the cheapest for both models, since they wrote less. Per-build values are
in `loop-measures.json`.

## Security, not compared

The protocol's security measures need a build `sv` could run. No build without the server could be run, so there is
nothing to compare them against; and Haiku plan 1's sixteen high findings are mostly the test passwords in its own
`test.py`, which `loop_measures.py` counts with the app's own code. Comparing security needs the arms without the
server to have a manifest: written for them by a tester, as trial 3 did, or the specification given in the request.
That is a choice for the owner before item 6.

## What went wrong in the run

- **The runner stopped at the first build with no `securevibe.toml`.** `tools/prompt_trial.py` now checks such a build,
  and one whose manifest does not parse, as it is, and records what `sv` said; the protocol already counted both as
  "could not start".
- **The `none` and `instructions` arms were measured on testability, which they could not have:** a build that has
  never seen `sv`'s format cannot write it. The protocol fixed this before any build and it is reported as it is; the
  backlog has the two ways to make the comparison mean more.

## Files

`run_arms.sh` made the builds and ran the checks; `loop_measures.py` and `loop_trial.py` are in
`docs/prompts/loop-pilot/`. `loop-measures.json` has every build's measures; `run-summaries.txt` is
`prompt_trial.py`'s per-check summary of each run, or what `sv` said when there was no report.
