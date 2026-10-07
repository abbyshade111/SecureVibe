# The prompts where every builder starts: protocol, written before it runs

The backlog's "Put the prompts shown to work where every builder starts" (6 October 2026), after the delivery test
(`delivery.md`) found a prompt pasted where the builder starts did better than one fetched mid-build. Fixed before any
build; a change made after a result is seen goes in "Amendments", dated, with its reason.

## The change tested

The coding prompts the library marks `shown` are given in full at the end of the two things every builder reads
before any code: the specification (`sv init`, `securevibe_spec`) and the MCP server's opening instructions, read from
`data/prompts.json`.

## How a build is made

As in `delivery-protocol.md`, Part B: headless Claude Code 2.1.286 on the owner's API credit, every MCP tool
attached, no prompt in the request, the plain brief with the owner-away sentence and `sv init`'s specification at the
top, in a fresh folder; `sv report --run` one build at a time, every build checked by the same `sv` (the new build).

- **One difference from the delivery test, for both arms alike:** the builder may run `git` as well as `python3`
  (`Bash(git:*)`), so that `git-from-the-start`, now given to every new-arm builder, can be followed. Two delivery-test
  builds stopped to ask for it; on the owner's computer it would simply run.

## The arms

- **today's `sv`:** `main` before this change (with ADR-044's brief and guidance), whose specification and
  instructions name no coding prompt;
- **at-start `sv`:** this change's build.

Claude Sonnet 5.5 and Claude Haiku 4.5, 10 builds an arm: 40 builds.

## The measures

As in `delivery-protocol.md`: for `ai-feature-guard` (Sonnet), `security-headers`, `private-pages-no-store`, and
`secrets-in-the-environment` (both models), the share of builds with the problem among those its check could be asked
of; harm (apps started, signed in to, running-app checks answered, and any app that refuses to start for a key `sv`
cannot give it); and, read from the code of builds 1, 4, and 7 of the at-start arm, whether each prompt was followed.

## The rule

For each prompt and model: delivery at the start **works** when today's `sv` has the problem in at least half of the
builds asked and the at-start `sv` in at most one in ten; **not shown** when today's has it in at least half and the
at-start one in more; **no reading** when today's has it in fewer than half. Harm as in `protocol.md`, reported with the
reading among apps that started beside it.

## Cost

About $0.40 a build with the server: about $16 for the 40, each capped at $1.50 ($60 at most). The owner approves the
size before the run.

## Amendments

None yet.
