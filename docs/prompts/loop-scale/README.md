# The loop at scale (5 and 6 October 2026)

Item 6 of the backlog's "The loop: `sv` as the MCP server an AI tool uses while it builds", run to
`docs/prompts/loop-protocol.md` with amendments 1 to 4. Five builds a cell, Claude Sonnet 5.5 and Claude Haiku 4.5,
on the plain brief with the sentence saying the owner is away, and, by amendment 3, `sv init`'s output (the
specification) at the top of every request. `sv` was the release build of `cd2478f8`: thirteen tools, with the
preflight (ADR-035) and instructions that say to check after each feature, fix, and check again. Each build was
checked with `sv report --run`, one at a time.

Seventy builds, $21.34 of the owner's API credit: the five arms (fifty builds, $15.70), and the check and plan arms
again with the tools they leave out hidden rather than refused (amendment 4: twenty builds, $5.64).

## What was seen

Running-app checks answered, each build (`answered` in `loop-measures.json`):

| Arm | What the builder had | Sonnet 5.5 | Haiku 4.5 |
|---|---|---|---|
| none | the specification, no server | 34, 32, 31, 34, 32 | 7, 29, 0, 24, 21 |
| instructions | and the server's instructions, no server | 33, 33, 29, 34, 30 | 21, 19, 0\*, 21, 36 |
| check, refused | the server; every tool but spec and check refused | 31, 33, 32, 32, 34 | 27, 0, 6, 26, 7 |
| check, hidden | the server; only spec and check shown | 32, 8, 29, 32, 32 | 7, 27, 18, 0\*, 6 |
| plan, refused | the server; every tool but spec and plan refused | 32, 35, 33, 32, 31 | 27, 21, 19, 21, 26 |
| plan, hidden | the server; only spec and plan shown | 34, 32, 30, 34, 32 | 0, 24, 26, 26, 6 |
| loop | the server, every tool | 33, 32, 29, 38, 33 | 33, 23, 23, 0, 22 |

\* Wrote `securevibe.toml` and no app: it stopped to ask the owner questions, though told the owner was away.
Unusable by the protocol's rule (stopped before writing an app), and reported here.

1. **With the specification in the request, every Sonnet build could be tested, in every arm,** about equally
   (29 to 38, but one at 8, which its own sign-in limit locked out). In item 3, without it, no build without the server could be tested at all. For Sonnet the
   specification does almost all of the work of making an app testable.
2. **Haiku varies widely within every arm,** and on testability no arm is above another by the protocol's rule. Of its six builds
   `sv` could not start, two wrote no app (above), three crashed when they started, and one wrote a manifest `sv`
   could not read (`can-act` under `[stack.run.ai]`).
3. **The loop arm checked, fixed, and checked again.** Every loop build called `securevibe_check` (one to three
   times); all five Haiku builds and two of five Sonnet checked again after a fix. In item 3, three of eight builds
   offered the check called it, once. Eight of ten loop builds also called `securevibe_preflight`.
4. **What the check said, the builders fixed.** In five loop builds `securevibe_check` named the `.gitignore` that
   does not cover `.env`; each wrote one, and the final report did not find it. Across the other arms the same high
   finding is in 56 of the 59 builds with a report; in the loop arm, 5 of 10. Haiku's loop builds also have no
   credential assigned in code, where Haiku's other arms have one in 12 of 29 builds. Neither is a difference by the protocol's
   rule on its own (some builds in other arms have none either); taken together with the code's other findings, they
   are ("Findings by group", below).
5. **Refusing a tool is not the same as hiding it** (amendment 4). With the tools they leave out still listed but
   refused, the check arm called the check in none of ten builds: the builders asked for the guidance and the
   preflight, as the instructions say, were refused, and concluded every SecureVibe tool was off limits ("The
   SecureVibe tools were denied in this mode"). With them hidden, Sonnet called the check in five of five and Haiku in
   one of five; and with the plan the only tool shown, eight of ten asked for it before writing code, against four of
   ten when the rest were refused. Item 3's check and plan arms were refused, not hidden: its finding that "the arms'
   own tools were mostly unused" is in part this.
6. **The plan did not change testability** for either model, refused or hidden.

## Why the low builds are low

- **Three Haiku apps crashed when they started** (check refused 2, plan hidden 1, loop 4). `sv` reports "Its last
  output was: Traceback (most recent call last):", which is the first line of the error, not the last: what went
  wrong is not said. Backlog.
- **Two Haiku builds wrote no app.** They stopped to ask about sign-up, passwords and sessions; each cost under $0.08.
- **Sonnet check hidden 2 (8):** the app's own limit on sign-in attempts answered `sv` with 429, and most signed-in
  checks could not be asked; the backlog has this already ("An app's own limit on sign-in attempts locks `sv` out").
- **The preflight would not have caught the builds with no app:** it checks that the seed's file is there, not the
  start command's. Backlog.

## Findings by group

Added on 6 October 2026, at the owner's asking, from the same seventy reports (`item6-findings.json`, every finding of
every build; `vuln_chart.py` draws `fig8-findings-by-group.png`). With every arm testable, the security measures can
be read for the first time, and they split in two.

**In the code, what `securevibe_check` can see, the loop arm had almost none.** Findings per build, low and above:

| Arm | Sonnet 5.5 | Haiku 4.5 |
|---|---|---|
| none (spec only) | 2.0 | 4.2 |
| instructions | 2.0 | 4.2 |
| check, refused | 2.0 | 5.6 |
| check, hidden | 0.8 | 3.2 |
| plan, refused | 2.0 | 6.0 |
| plan, hidden | 2.0 | 4.8 |
| **loop** | **0.6** | **0.4** |

Builds with each, of ten per arm: the committable `.env` (high) 8 to 10 in every other arm, 5 in the loop; a weak
password key derivation (medium) 2 to 5, and 0; a credential assigned in code (high) 1 to 3, and 0; no security contact
(low) 4 to 10, and 0. **By the protocol's rule this is a difference, the first in the loop trials:** counting findings
of every severity, every loop build has fewer than every build of five of the other six arms, for both models. The
arm it is not below is check hidden, the other arm whose builders ran the check. Counting medium and high only, it
holds for Haiku against check refused, plan refused, and plan hidden, and not for Sonnet, where nearly every build in
every arm has the one `.env` finding. So what can be said is that builders that ran the check fixed what it named, and
the code shows it; not that the apps became safer in general.

**In the running app, what only `sv run` sees, every arm is the same.** Findings per ten checks answered, medium and
above: Sonnet 0.8 to 1.1 in every arm (loop 1.0), Haiku 2.0 to 2.6 (loop 2.4). The most common: the AI feature passing
hidden instructions on, or giving its own away (3 to 7 builds an arm); missing security headers; no limit on wrong
passwords (2 to 4 an arm, the loop 4). The model matters far more than the arm: Haiku's apps have about two and a half
times Sonnet's.

**Why.** `securevibe_check` reads files; the running-app checks happen in `sv run`, which the MCP server does not
start, so nothing tells the builder about them. The loop fixes what it is told. The backlog has the next step: say
before the build ends what the code can already show about the running app.

## Cost and time

Per build: Sonnet $0.22 to $0.53, Haiku $0.04 to $0.57 (the two that wrote no app were the cheapest). Sonnet builds
took one and a half to three minutes, Haiku's from under half a minute to four and a half; `sv report --run` took two
to five minutes each, about four hours in all.

## Files

`run_item6.sh` made the fifty builds and ran their checks; `run_hidden.sh` and `check_hidden_after.sh` the twenty
with hidden tools. `loop_trial.py` and `loop_measures.py` are in `docs/prompts/loop-pilot/`, now with `--with-spec`,
the hidden arms, and the measures `preflight_calls` (calls asked for, refused ones included) and
`checked_again_after_a_fix`. `loop-measures.json` has every build's measures; `run-summaries.txt` is
`prompt_trial.py`'s per-check summary of each run.
