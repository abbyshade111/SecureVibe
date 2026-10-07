# The prompts where every builder starts (7 October 2026)

Run to `start-protocol.md`, decided before any build: 40 headless Claude Code builds with every MCP tool attached,
today's `sv` (`0c7e1448`, which gives the shown prompts in the feature briefs and the guidance, ADR-044) against the
at-start `sv` (`44374dd0`, which also gives them in full at the end of the specification and the opening
instructions), Sonnet 5.5 and Haiku 4.5, 10 builds an arm, `git` allowed in both. Every build was checked by the
at-start `sv`. **$18.11** of the owner's API credit ($9.25 and $8.86). No transcript holds the key.

**A departure from the loop protocol, found while writing this up.** Its Amendment 5 (6 October 2026, 13:21 UTC, by
another session) strengthened the owner-away sentence "for every trial after". This test and the delivery test before
it (`delivery.md`) used the earlier sentence, because the build script they ran from was copied before that change.
Both arms of each test had the same sentence, so each comparison holds; how many builds stopped to ask may differ from
what Amendment 5's wording would give. The script is up to date for every trial from here on.

## Results, by the protocol's rule

| Prompt | Model | Today's `sv` | At-start `sv` | Verdict |
|---|---|---|---|---|
| `secrets-in-the-environment` | Sonnet | 9 of 10 | **0 of 10** | **works** |
| `ai-feature-guard` | Sonnet | 8 of 8 | 9 of 10 | not shown |
| `private-pages-no-store` | Haiku | 3 of 8 | 1 of 6 | no reading |
| `security-headers` | Haiku | 1 of 10 | 0 of 7 | no reading |
| `secrets-in-the-environment` | Haiku | 1 of 10 | 4 of 10 | no reading |
| `security-headers`, `private-pages-no-store` | Sonnet | 0 of 10 | 0 of 10 | no reading |

Counts are builds with the problem, of those the prompt's check could be asked of. Recounted on 7 October 2026
(`revision-protocol.md`, Amendment 2): `private-pages-no-store` on Haiku was first scored 3 of 6 and 1 of 5, "not shown";
counted by `sv` signing in, as `protocol.md` defines it, fewer than half of the builds without it had the problem.

## What lies under the verdicts

- **Keys and `.env`, Sonnet: works.** Without the prompts at the start, nine of ten Sonnet builds left `.env`
  committable; with them, none did. In the delivery test the same prompt, given only in the guidance, changed nothing
  for Sonnet (9 of 10). This is the first delivery through `sv` the rule calls working.
- **The AI feature, Sonnet: two of its three problems went.** With the prompts at the start, no Sonnet app passed a
  prompt injection to the model (2 of 10 today) or passed on its instructions (4 of 10 today); a reply's hidden
  characters still reached the page in 9 of 10 (8 of 10 today). The rule counts a build with any of the three, so it
  says "not shown". Pasted into the request, the same prompt removed all three (`README.md`).
- **Haiku's baseline had moved.** With `git` allowed and the guidance giving the shown prompts, today's `sv` already
  left Haiku's apps with missing headers in 1 of 10 and a secrets finding in 1 of 10 (9 of 9 and 8 of 9 in the
  delivery test's arm with `sv` before ADR-044, where `git` was not allowed). So most Haiku comparisons have no reading: the problem was no longer common
  enough to show a prompt removing it.
- **Haiku's secrets count rose, and none of it is a secret.** Twelve findings in three builds: eight in one build at
  `value="{html.escape(csrf_token)}"`, the anti-forgery token a form carries, which `sv`'s credential rule reads as a
  token written into the code; four were made-up passwords in tests (`test_password_123`). `sv`'s false alarm is in
  the backlog.
- **Harm: none from the prompts.** Haiku's at-start arm started 7 apps against 10; the three that did not crashed on
  ordinary faults of their own code (an import, a database table, an attribute), none tied to a prompt. No app refused
  to start for a key `sv` cannot give, as one did in the delivery test.

## What follows

- **The prompts at the start are worth keeping:** the one comparison with room to show it works, and none shows harm.
- **The hidden-characters part of `ai-feature-guard`** is the part a builder misses unless the prompt is in the
  request itself. A check of its own at the start, or the AI brief offering it when the AI feature is built, is the
  next thing to try.
- **`sv`'s credential rule should not read a template's `{...}` placeholder for a token as a credential.**

## Files

`start-protocol.md`; `run_start.sh`; `score_start.py`; `start-verdicts.json`; `start-summaries.txt`.
