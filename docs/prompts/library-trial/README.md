# The prompt-library trial (6 October 2026)

Items 2 and 3 of the backlog's "Test the prompt library where the prompts have something to fix", run to
`protocol.md` in this folder, decided before any build. Ninety headless Claude Code builds (2.1.286) of the loop
trials' club app, each in a fresh folder with no MCP server, the specification and the owner-away sentence in every
request, and one library prompt added in a prompt's arm; each checked with `sv report --run` from `sv` `a9d6fea4`.
**$21.12** of the owner's API credit (an average of $0.235 a build; the most, $0.61). No transcript holds the key.

## Results, by the protocol's rule

| Prompt | Model | Problem without it | With it | Rule's verdict | Library now |
|---|---|---|---|---|---|
| `ai-feature-guard` | Sonnet 5.5 | 10 of 10 | 0 of 9 | **shown**, no harm | **shown** |
| `security-headers` | Haiku 4.5 | 6 of 6 | 0 of 6 | **shown**, harm flag | **shown** (owner) |
| `private-pages-no-store` | Haiku 4.5 | 5 of 5 | 0 of 4 | **shown**, harm flag | **shown** (owner) |
| `secrets-in-the-environment` | Haiku 4.5 | 6 of 6 | 1 of 4 | **shown**, harm flag | **shown** (owner) |
| `password-hashing` | Haiku 4.5 | 4 of 6 | 2 of 8 | no reading | not shown |
| `sessions-hard-to-steal` | Haiku 4.5 | 4 of 5 | 1 of 4 | no reading | not shown |
| `design-limits` | Haiku 4.5 | 5 of 5 | 2 of 2 | not shown, harm | shown, with a warning (owner) |

"Problem" counts the builds the prompt's check could be asked of: a readable `securevibe.toml`; for a running check,
an app that started; for a signed-in or AI check, one whose sign-in or AI feature answered. "No reading": the builds
without the prompt had the problem in fewer than five, so the brief did not tempt the shortcut enough this time.
Fisher's exact test, for those who want it, is in `verdicts.json` (0.0000 for the AI prompt, 0.002 to 0.03 for the
three Haiku ones shown).

## The harm flags, read

The rule flags harm when a prompt's arm is behind by 3 of 10 in apps started or signed in to, or by a median of 5
running-app checks answered. It flagged five of the six Haiku prompts, and the median counts an app that never started
as none. **Among the apps that started, every prompt's builds answered as many checks as the no-prompt builds, or
more** (medians 21 to 26 against 20). Most of the apps that did not start had a `securevibe.toml` `sv` could not read,
which happened in every arm, the one without a prompt included (below). At the owner's decision, the three prompts
shown with a flag are marked shown, each with the flag and this reading recorded in the library.

Two of the flags are real and are said so:
- **`design-limits`** asks the owner for the limits. With the owner away, six of its ten builds stopped to ask and
  wrote nothing. It stays shown (from trial 3, with an owner to answer), with a warning in `docs/prompts/design-time.md`.
- **`secrets-in-the-environment`**: six of its ten builds wrote a `securevibe.toml` `sv` could not read, against three
  of ten without a prompt. Chance at this size, or the prompt crowding out the specification; to be checked again.

## Did the builders do what the prompts said

Read in builds 1, 4, and 7 of each Haiku arm, chosen before any result: most did what their prompt asked. Four did
not, all said: one secrets build left `.env` out of `.gitignore`; one password-hashing build (7) used PBKDF2, which
the prompt does not name (it asks for Argon2id, bcrypt, or scrypt); and design-limits' builds 1 and 7 wrote nothing.

## What else it found

**A third of Haiku's builds wrote a settings file `sv` cannot read**, whatever the prompt: 22 of 70, most often
`enabled = true` under `[stack.run.ai]` (14) and `signup = false` (2). `sv`'s message says exactly what is wrong
("Did you mean [capabilities.ai]?"), but these builders had no `sv` to hear it. In the backlog.

**The runner crashed on a build that wrote nothing,** stopping the remaining 80 checks for about an hour;
`tools/prompt_trial.py` now commits an empty build and records that it had no report.

## Files

`protocol.md` (written before any build); `run_prompt_trial.sh` (the builds and checks); `score_prompt_trial.py` (the
rule, applied); `verdicts.json` (every build's measures and each prompt's verdict); `run-summaries.txt` (each run's
per-check summary). The build script is `docs/prompts/loop-pilot/loop_trial.py`, now with `--prompt`.
