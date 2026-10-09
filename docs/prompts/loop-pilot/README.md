# The loop pilot (5 October 2026)

Items 2 and 4 of the backlog's "The loop: `sv` as the MCP server an AI tool uses while it builds", run to
`docs/prompts/loop-protocol.md`, **loop arm only**. Each build was made by the Claude Code program the desktop app
carries (2.1.286), headless, in a fresh folder, given only the plain brief (`docs/prompts/trial-3/plain-brief.md`) as
its request and `sv mcp` attached for that run. The request says nothing about `sv`'s tools: whatever the builder did
with them, the server's own instructions led it to. Every build was then checked with `sv report --run`.
`sv` was the release build of `87404c8e`.

One tool, two models of one vendor, six builds. This describes what was seen; the protocol allows no "better" from
fewer than five builds a cell, and there is only one arm here.

## What was seen

| Build | `sv` tools before the first line of code | `sv check` calls | Wrote an app | Started; `sv` signed in | Running-app checks answered | Cost, time |
|---|---|---|---|---|---|---|
| Sonnet 5.5, 1 | spec, guidance, `before` ×5 | 1 | yes | yes; yes | 34 | $0.41, 2 min |
| Sonnet 5.5, 2 | spec, guidance, `before` ×5 | 1 | yes | yes; yes | 38 | $0.39, 2 min |
| Haiku 4.5, 1 | spec, questions ×3 | 0 | **no**: stopped to ask the owner | - | - | $0.06, 1 min |
| Haiku 4.5, 2 | spec, guidance, **plan**, `before` ×2, notes file | 0 | **no**: stopped to ask the owner | - | - | $0.11, 1 min |
| Haiku 4.5, 3 (amended) | spec, plan and guidance ×6 (five refused: see below), `before` ×3 | 1 | yes | yes; yes | 21 | $0.45, 4 min |
| Haiku 4.5, 4 (amended) | spec, `before` ×4, guidance ×6, notes file, 8 answers recorded | 0 | yes | yes; yes | 27 | $0.44, 5 min |

Total spent: $1.86 of the owner's API credit, against a cap of $3 a build.

1. **Every build used `sv` before writing any code, without being asked.** All six read the specification first, and
   all but one read the guidance or `before` for its features. Two read the plan.
2. **The Haiku builds did what `sv` says and stopped.** The server says to settle the design with the owner before
   building. Haiku asked the owner about sign-in limits, session times, and who may do what, and ended its turn. A
   headless build has no owner to answer, so these two are unusable by the protocol's rule (stopped before writing an
   app) and are reported here, not scored. The request was amended (below) and two more builds were made.
3. **With the amendment, both Haiku builds wrote down their decisions in `sv`**: ten and eight answers recorded with
   `securevibe_record_answer` (Haiku 4 before writing any code, Haiku 3 after), and a notes file each. The Sonnet builds, which had not been told the owner was away,
   recorded none.
4. **Testability.** All four builds that wrote an app started and could be signed in to. Sonnet's 34 and 38 are as
   high as the third trial's best (9 to 36 there); Haiku's 21 and 27 are close to its MCP-approximation builds (26 and
   26 there). Both are counts of two.
5. **Only three of six builds ran `sv check`,** each once, near the end. No build had a second check-and-fix round, so
   the loop as designed (check, fix, check again) was not seen. The three checks reported no requirement needing
   attention and one low finding.

## Findings in the apps

Every build that `sv report` saw (including the two with no app, which had a `securevibe.toml`) was flagged for
nothing stopping `.env` being committed (`config.gitignore-covers-env`, high). The `sv check` during the build did not
say so, because the build's folder was not a git repository; `prompt_trial.py` makes each copy one. Others, from the
running app: weak session IDs in both Sonnet builds (high); no limit on wrong passwords and session-cookie attributes
in Haiku 3 (high); a credential assigned in code twice in Haiku 4 (high, own code); and `probe.action-done-twice` in
Sonnet 2, which is the known false alarm in the backlog. `run-summaries.txt` has every check per build.

## What went wrong, and what was changed

- **The headless program was not signed in.** The desktop app's sign-in does not reach the same program run from a
  terminal. The owner chose to run the pilot on their API credit instead (amendment 2 in the protocol). The key is
  given to the program by an `apiKeyHelper` (`key_helper.sh`), so it is never in the environment of the builder's
  shell, the app, or `sv`. Every transcript was searched for the key afterwards: none holds it.
- **No owner to answer** (amendment 1): every build's request now ends with *"I won't be around to answer questions
  while you build; where something needs deciding, choose the safer option and write down what you chose."* Haiku 1
  and 2 were made before it, Haiku 3 and 4 after it, and Sonnet 1 and 2 before it; the Sonnet builds were not made
  again, since they never stopped to ask.
- **Haiku 3 sent the same broken `securevibe.toml` to `sv` five times.** `sv`'s message named the line and the field
  (`enabled`) and listed the fields allowed, but not the section (`[stack.run.ai]`) it was read in; Haiku kept moving
  the line within the wrong section. Backlog.
- **`sv`'s plan was too big for the tool to take in:** 115,618 characters, which Claude Code saved to a file instead
  of passing on, and `sv check`'s answer for Haiku 3 was 50 KB, handled the same way. The builder then read both in
  parts with `python3`. Backlog.
- **`python3` is not confined to the build's folder,** and one build used it to read Claude Code's saved copy of the
  plan from its own folder under `~/.claude/projects`. No build wrote outside its folder.
- **The measures script first read the check's answer as text;** it is JSON. Fixed before the results here were
  computed.

## Files

`loop_trial.py` makes a build (`--api` for API credit, `--before-amendment-1` for the pilot's first request);
`loop_measures.py` computes the measures from the transcripts and reports into `loop-measures.json`, with
`loop_dodging.py`'s two added on 9 October 2026 (gap analysis finding 21): how each finding went away between one
check and the next (`set-aside`, `file-removed`, `code-changed`, or `unexplained`), and the edits that seek credit
(requirement ids written into tests, `by = "owner"`, finding reviews, `not-the-app`, and scope lines). The
`loop-measures.json` files kept here were written before then and do not have them;
`key_helper.sh` is the `apiKeyHelper`; `run-summaries.txt` is `prompt_trial.py`'s per-check summary of each run. The
builds and transcripts are not kept in the repository.
