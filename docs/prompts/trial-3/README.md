# The third prompts trial (5 October 2026)

Item 7 of the backlog's "Design-time help before any code", run at the size the owner chose: two models (Claude
Sonnet 5.5 and Claude Haiku 4.5, as helper agents of one Claude Code session), two builds per arm. Every build was
checked with `sv report --run` behind the fence, from `sv` at `d22fb6d3`.

It asks two questions:

1. **Do the design-time prompts that have a check change what is built,** with models other than the one that built
   the first two trials? (Part 1.)
2. **Does the help before any code (the plan, or the MCP server's instructions) make an app that `sv run` can test?**
   (Part 2.)

One tool, two models of one vendor: nothing here speaks for other vendors' tools.

## Part 1: the prompts, on the first trial's brief

The brief is `docs/prompts/trial/brief.md`, unchanged, with `docs/prompts/trial/securevibe.toml` and no [policy]
numbers; where a build wrote none, `docs/prompts/trial/policy.toml` stood in for the owner's, as before. Arms: no
prompt, and each of prompts 1, 3, 4, 6, and 7 (the five with a check that can show them working). Prompt 2 was left
out: `probe.action-done-twice` still counts a correct booking as twenty (BACKLOG), so its arm would have measured that
false alarm. The prompt-7 builds and, for that prompt only, copies of the builds without a prompt (`baseS`) were run
with `--slow`, since its checks wait out the session times.

The rule is the library's: a prompt is shown to work for a check, for one model, when every build made with it was
credited by that check and every build made without any prompt was not. A build `sv` could not start, or could not
sign in to, says nothing about these checks and is left out.

| Prompt | Check | Sonnet 5.5 | Haiku 4.5 |
|---|---|---|---|
| 1, who may do what | four access checks | no difference: built without it, already passed | no difference (one build with it unusable) |
| 3, limits on abuse | `probe.create-rate-unlimited` | **shown** | not shown: one build refused with 403, not 429 |
| | `probe.failed-sign-ins-unlimited` | **shown** | not shown: one build with it was found with no limit on wrong passwords |
| 4, when things fail | `probe.error-detail-leak`, `probe.ai-service-failure-handled` | no difference | no difference |
| | `probe.ai-service-error-shown` | no reading either way | no reading either way |
| 6, logging | `probe.log-line-metadata`, `probe.log-timestamp-zoned` | **shown** | **shown** |
| | `probe.authorization-failure-logged` (V16.3.2) | **shown** | not shown: one of two builds with it |
| 7, sign-in | `probe.session-idle-timeout` (V7.3.1) | **shown** | **shown** |
| | `probe.session-lifetime` (V7.3.2) | not assessed: the prompt's 12 hours is longer than `--slow` waits | the same |
| | `probe.logout-keeps-session` | no difference | no difference |
| | the three token checks | no reading: no build issued its own tokens | the same |

`prompt-scores.txt` has every check per build; `prompt-verdicts.json` the same as data.

**What it shows.** The three prompts shown to work in the first trial (3, 6, 7) held for Sonnet 5.5 on every check
they were shown on, and prompt 6 now also on V16.3.2, which the first trial could not claim because one build without
the prompt logged the refusal by itself. For Haiku 4.5, 6 and 7 held; 3 did not, because one of its two builds with
the prompt did not do what the prompt asks (answer 429). Prompts 1 and 4 made no difference with either model, as in
the first trial: the builds without them were already safe on what `sv` checks.

## Part 2: whether the help before any code makes an app `sv run` can test

The first brief already tells the builder how to be tested (the forms, `seed.py`), so it cannot show this. Part 2 used
a plainer brief (`plain-brief.md`): the same app, described as an owner would, with the environment's fixed facts and
no hint of what a tester needs. Every build was given `sv init`'s specification and wrote its own `securevibe.toml`.

- **no plan**: the specification only, which is what `sv` offered before the plan;
- **plan**: told to write the brief first, run `sv plan .`, and build to it;
- **MCP flow, approximated**: given the MCP server's opening instructions as written, and the `sv` command line in
  place of the tools (`sv init`, `sv plan .`, `sv prompts`, `sv rules .`, `sv questions .`, `sv check .`). This
  shows whether the instructions work when read, not whether a tool connected to the server reads them unasked: a
  helper agent cannot be given an MCP server without changing the session's configuration.

What was measured: how many distinct checks of the running app answered at all, credited or found (`answered.txt`).
The settings themselves (`testability.txt`) told nothing: almost every build gave all twelve, because the
specification already lists them.

| | no plan | plan | MCP flow, approximated |
|---|---|---|---|
| Sonnet 5.5 | 9 and 30 | 32 and 31 | 22 and 36 |
| Haiku 4.5 | 29 and 6 (sign-in failed) | 7 and 8 (sign-in failed in both) | 26 and 26 |

**What it shows, and what it does not.** With Sonnet the plan made both builds testable to the same high level, where
the builds without it varied widely; the low one locked `sv` out with its own sign-in limit, which the plain brief
did not warn of (the first brief did). With Haiku the plan did not help: in both plan builds `sv` could not sign in,
so most checks had nothing to work with. Given the MCP instructions and the command line, both Haiku builds came out
testable, at 26 each. Two builds a cell is enough to see these differences and not to say they would hold.

## What went wrong in the trial, and what was done

- **The trial ran from `/tmp` first, and Colima shares only the home folder,** so every app's folder was empty inside
  its container. `sv` said exactly that, and reported every check not assessed. The trial was moved under the home
  folder and run again.
- **The first brief says `seed.py` runs "before the app starts"; `sv` runs it after the app answers its health path**
  (`sv-run/src/docker.rs`), and `sv`'s specification does not say when. Haiku builds that made their tables only in
  `seed.py` crashed on the first page: both builds without a prompt, and one with prompt 1. They were rebuilt with
  that one sentence corrected (`baseC-1`, `baseC-2`, `p1C-2`), and Haiku's comparisons use the rebuilds. The gap in
  the specification is in the backlog. No Sonnet build depended on it: each made its own tables at start.
- **The slow runs.** At first only the prompt-7 builds ran with `--slow`, so the builds without a prompt had no
  reading on the session times. They were run again with `--slow` (`baseS`) and prompt 7 compared with those.
- **Builders tested their own apps outside the command sandbox,** because it blocks opening a port; one used a port
  other than the one it was given. No two collided, and every builder reported nothing left running. One builder was
  refused a command it tried for reading the plan's tests, so it read the plan only in part.

## Cost

Thirty-nine builds (thirty-six, and three rebuilt), by helper agents of this session: between about 68,000 and
144,000 tokens each, roughly 3.5 million in all, on the session's usage rather than the owner's API key. Every `sv`
run was free.

## Files

`plain-brief.md` (Part 2's brief), `score_prompts.py` and `testability.py` (the scoring, run over the folder that
`tools/prompt_trial.py` writes `runs/` into), and the results: `prompt-scores.txt`, `prompt-verdicts.json`,
`answered.txt`, `testability.txt`, `testability.json`. The builds themselves are not kept in the repository.
