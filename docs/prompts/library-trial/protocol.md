# The prompt-library trial: protocol, written before it runs

Item 2 of the backlog's "Test the prompt library where the prompts have something to fix" (6 October 2026). Fixed
before any build. A change made after a result has been seen goes in "Amendments", dated, with its reason, and the
result is reported both ways where it can be (as in `loop-protocol.md`).

## The question

For each prompt tried: **does giving it to the AI coding tool make the problem it is for go away, without making the
app worse in another way?** The earlier trials could not say, for eleven of the library's prompts, because the build
without the prompt was already safe. This trial tries each prompt where item 6 of the loop trials found the problem
in most builds without it.

## How a build is made

- **The builder** is the headless Claude Code of the loop trials (`docs/prompts/loop-pilot/loop_trial.py`), on the
  owner's API credit through the `apiKeyHelper`, in a fresh folder under the home folder, with no MCP server: the
  prompt is the only thing that differs between arms, and nothing else of `sv` reaches the builder.
- **The request** is the loop's plain brief (`docs/prompts/trial-3/plain-brief.md`) with the sentence saying the owner
  is away (loop amendment 1) and `sv init`'s specification at the top (loop amendment 3), so every build can be
  tested. In a prompt's arm, the prompt's text is added at the end, after "Follow this while you build:".
- **`sv`** is one release build from `main`, its commit recorded with the results, the same for every build.
- **The check** is `sv report --run` through `tools/prompt_trial.py`, with `docs/prompts/trial/policy.toml` standing in
  for any [policy] number a build did not write, one build at a time.

## The arms

Each prompt is tried on the model whose builds had its problem in item 6 (the builds without the server, which had
the specification and no prompt):

| Arm | Model | Its check (`sv` rules) | Item 6 without it |
|---|---|---|---|
| no prompt | Haiku 4.5 | (every rule below) | — |
| `password-hashing` | Haiku 4.5 | `ast.weak-hash-function`, `ast.weak-password-key-derivation` | 6 of 9 |
| `secrets-in-the-environment` | Haiku 4.5 | the `secrets.` rules, `config.gitignore-covers-env` | 9 of 9 (a key in the code in 4) |
| `security-headers` | Haiku 4.5 | `probe.security-headers` | 8 of 8 |
| `design-limits` | Haiku 4.5 | `probe.failed-sign-ins-unlimited`, `probe.create-rate-unlimited` | 5 and 6 of 8 |
| `sessions-hard-to-steal` | Haiku 4.5 | `probe.session-cookie-attributes`, `probe.session-id-weak`, `probe.logout-keeps-session` | 5 of 8 |
| `private-pages-no-store` | Haiku 4.5 | `probe.private-page-cached` | 6 of 8 |
| no prompt | Sonnet 5.5 | `probe.ai-*` below | — |
| `ai-feature-guard` | Sonnet 5.5 | `probe.ai-injection-unscreened`, `probe.ai-instructions-leaked`, `probe.ai-hidden-content-passed` | 8 to 10 of 10 |

Ten builds an arm: 90 builds. Left out, with the reason: `changes-from-own-pages` (item 6 had its problem in 2 of 8
Haiku and 0 of 10 Sonnet builds, so this brief cannot show it working; it needs a brief that tempts the shortcut),
`design-sign-in` (its check waits out the session times under `--slow`, about ninety minutes a build), and the eight
design prompts no check can see.

## The measures

From each build's `report.json` and transcript (`loop_measures.py`, extended for this trial):

1. **The prompt's own check:** for each build, whether any of its rules is a finding, among the builds where the check
   could be asked (the app started; for a signed-in check, `sv` signed in; for the AI checks, the AI feature answered).
2. **Harm, in the same builds:** whether the app started and could be signed in to; the running-app checks answered;
   and every finding at medium or above that is not one of the prompt's own rules.
3. **Did the builder do what the prompt says:** read from the code by hand for three builds an arm, chosen before any
   result is seen (builds 1, 4, and 7), so a prompt that was followed and still failed its check can be told from one
   that was ignored.
4. **Cost and time,** from the transcript.

## What makes a build unusable, decided now

As in the loop protocol: a build that wrote no app is left out of everything and reported; a build `sv` could not
start, or not sign in to, counts for harm as it is and is left out of a check it could not be asked.

## The rule, decided now

For each prompt, comparing its arm with the no-prompt arm of the same model:

- **Shown to work** when the problem was there in at least 5 of the no-prompt builds the check could be asked of, and
  in at most 1 of the prompt's. The library's `status` becomes `shown`, and `tested` records the trial.
- **Not shown** when the no-prompt builds had it in at least 5 and the prompt's in 2 or more.
- **No reading** when the no-prompt builds had it in fewer than 5: the brief did not tempt the shortcut this time.
- **Harm** is reported for every arm, and called harm only when the prompt's arm is worse than the no-prompt arm by
  at least 3 builds of 10 in being started or signed in to, or by a median of 5 or more running-app checks answered.
  A prompt shown to work and harmful is reported as both, and is not marked `shown` until the owner has decided.

Fisher's exact test is reported beside each comparison, for a reader who wants it; the rule above is what decides.

## Cost

About $0.30 a build in item 6 for these models without the server: about $27 for the 90 builds. Each build is capped at
$1.50 (`--max-budget-usd`), $135 at most. The owner approves the number of builds and the estimate before the run. If
the first ten builds average more than $0.60, the run stops and the owner is told before more is spent.

## Amendments

None yet.
