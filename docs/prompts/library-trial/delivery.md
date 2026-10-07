# The delivery test, and the settings-file check (6 October 2026)

Run to `delivery-protocol.md`, decided before any build. Sixty headless Claude Code builds of the club app, each
checked with `sv report --run` by the same `sv` (`0c7e1448`, the delivering build). **$19.36** of the owner's API
credit: Part A $4.28, Part B $15.08. No transcript holds the key.

## Part A: the specification's fix for unreadable settings files

20 Haiku 4.5 builds, no server, no prompt, with the two new sentences in the specification.

| | Before (prompt-library trial) | After |
|---|---|---|
| Wrote a `securevibe.toml` `sv` could not read | 22 of 64 (34%) | **3 of 20 (15%)** |
| `enabled` under `[stack.run.ai]`, or `signup` true or false | 16 | **0** |
| App started under `sv run` | 6 of 10 (no-prompt arm) | **17 of 20** |

**Verdict: partly**, by the rule. Both mistakes the sentences name are gone; three files were still unreadable,
one more than the rule allows for "works": two repeated a key, one wrote `ai = true` under `[capabilities]` (it is
`enabled = true` under `[capabilities.ai]`). Fisher's exact test on the unreadable files: p = 0.16, so at 20 builds the
fall is seen, not shown.

## Part B: does `sv` deliver the prompts so that they work?

Every MCP tool attached, no prompt in the request: today's `sv` (`a9d6fea4`) against the delivering one (ADR-044),
10 builds an arm, Sonnet 5.5 and Haiku 4.5.

| Prompt (how ADR-044 delivers it) | Model | Today | Delivering | Pasted (prompt-library trial) |
|---|---|---|---|---|
| `ai-feature-guard` (AI brief) | Sonnet | 10 of 10 | 10 of 10 | 0 of 9 |
| `security-headers` (guidance) | Haiku | 9 of 9 | **2 of 6** | 0 of 7 |
| `secrets-in-the-environment` (guidance) | Haiku | 8 of 9 | **4 of 9** | 1 of 4 |
| `secrets-in-the-environment` (guidance) | Sonnet | 10 of 10 | 9 of 10 | (not tried) |
| `private-pages-no-store` (sign-in brief) | Haiku | 3 of 7 | 2 of 5 | 0 of 6 |
| `security-headers`, `private-pages-no-store` | Sonnet | 0 of 10 | 0 of 10 | (no problem to fix) |

Counts are builds with the problem, of those its check could be asked of (recounted on 7 October 2026,
`revision-protocol.md`, Amendment 2: `private-pages-no-store` on Haiku, first 3 of 6 and 2 of 4, moves from "not
shown" to "no reading", since fewer than half the builds without it had the problem). **By the rule, delivery is not shown to
work for any prompt.** Why, from the transcripts:

1. **The briefs mostly never reached the builders.** `securevibe_before` refuses until `securevibe.toml` exists, and
   with the specification already in the request the builders asked for the briefs first, before writing it: "there
   is no securevibe.toml ... write the file it describes ... and check again." Few asked again. The AI brief with
   its prompt reached 2 of 10 Sonnet builds and 3 of 10 Haiku; the sign-in brief 2 of each. The two Sonnet builds
   that did get the AI prompt fixed two of its three problems (the injection reached the model in neither, and neither
   passed on its instructions) and kept the third (a reply's hidden characters reached the page): delivered, it partly
   worked; it was seldom delivered.
2. **The guidance did reach them** (10 of 10 Sonnet, 7 of 10 Haiku: it needs no settings file), and halved Haiku's
   problems, though less than pasting the same prompt did: the headers in 2 of 6 against 0 of 6 pasted, keys or `.env`
   in 4 of 9 against 1 of 4. For Sonnet, the guidance's secrets prompt changed nothing (9 of 10): almost every build
   still left `.env` out of `.gitignore`.
3. **Harm, from following the delivered prompts.** One Haiku app would not start: "SECRET_KEY environment variable
   must be set", which is what `secrets-in-the-environment` asks ("stop with a clear message if one is missing"), but
   `sv run` gives an app none of its own keys. Two Haiku builds stopped before writing an app to ask permission to run
   `git`, which `git-from-the-start` asks for and this trial's shell does not allow (on the owner's computer it would).
   Haiku's delivering arm started 6 apps against today's 9.

## What follows

- **A prompt pasted where the builder starts works better than one fetched mid-build,** in every comparison here.
  The two places every builder reads before any code are the server's opening instructions and the specification.
- **`securevibe_before` should answer before `securevibe.toml` exists**, with what a feature brings regardless of the
  app, or the briefs will keep missing the builders who most need them.
- **`secrets-in-the-environment` needs one more line** for keys an app makes for itself (a session secret): make one
  at first start when none is set, rather than refusing to start.

Each is in the backlog.

## Files

`delivery-protocol.md`; `run_delivery.sh`; `score_delivery.py` (Part B's rule); `delivery-verdicts.json`;
`delivery-summaries.txt` (each run's per-check summary, by part).
