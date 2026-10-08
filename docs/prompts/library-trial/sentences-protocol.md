# The three sentences: protocol, written before it runs

At the owner's word of 7 October 2026 ("go ahead with the small trial", choosing "All three, about $13.50"): the three
sentences added to prompts on 7 October 2026 from what the revision and recipe trials found, each marked untried in the
library. Fixed before any build; a change after a result is seen goes in "Amendments", dated, with its reason.

## The arms

Ten builds an arm, built as in `recipe-protocol.md` (headless Claude Code 2.1.286, no MCP server, `git` allowed, the
owner-away sentence, `sv init`'s specification from `main` at the top, packages refused on this computer), with the
prompt's text after "Follow this while you build:". Every build is checked by `sv report --run` from one release build
of `main`, its commit recorded.

| Arm | Model | Brief | The sentence tried | Its check | Compared with |
|---|---|---|---|---|---|
| `password-rules` | Sonnet 5.5 | recipe | use `zxcvbn==4.5.0`'s list | `probe.short-password-accepted`, `probe.common-password-accepted`, `probe.password-altered` | the recipe trial's Sonnet baseline: 10 of 10 |
| `production-server` | Sonnet 5.5 | recipe | one worker with SQLite, or tables made first | `probe.content-type`, `probe.version-disclosed` | the recipe trial's Sonnet baseline: 5 of 10 |
| `isolate-the-window` | Haiku 4.5 | club (`trial-3/plain-brief.md`) | headers on Python's own error pages | `probe.opener-policy-missing`, `probe.csp-no-report` | the revision trial's Haiku baseline: 7 of 7 (and its arm with the earlier text: 4 of 10) |

**The baselines are earlier trials', a choice made to keep the trial small, and each comparison says so.** They were
built with an earlier `sv` and its specification. One difference matters and runs against the prompt: the
common-password check now tries three words (ADR-055), where the recipe baseline's tried one, so `password-rules`'s
arm is held to a stricter check than its baseline was. The other checks are unchanged since their baselines.

## The rule

As every trial: **shown** when the baseline had the problem in at least 5 of the builds asked and the arm in at most 1;
**not shown** when the arm had it in 2 or more. Harm as in `recipe-protocol.md`. For `production-server`, how many
apps did not start for "database is locked" is reported beside it (1 of 10 with the earlier text). For
`isolate-the-window`, whether the error pages carry the header is read by hand in builds 1, 4 and 7.

**Also measured, in the two recipe arms:** how many builds declared their upload and listed a search page with a term
in securevibe.toml (3 of 10 and 1 of 10 in the recipe trial), the first reading of the specification's new wording.

## Cost

About $0.65 a Sonnet build with `password-rules` and $0.42 with `production-server`, and $0.28 a Haiku build (the
earlier trials): about $13.50 for the 30. Each build is capped at $1.50; an arm stops if its ten average more than
$0.80 (Sonnet) or $0.60 (Haiku). The owner reported $67.31 of credit before the run.

## Amendments

None yet.
