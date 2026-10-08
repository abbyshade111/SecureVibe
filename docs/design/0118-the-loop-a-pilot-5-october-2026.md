# The loop, a pilot (5 October 2026)

Items 2 and 4 of "The loop", to `docs/prompts/loop-protocol.md`, loop arm only (`docs/prompts/loop-pilot/README.md`
has the table and files). A headless Claude Code (2.1.286), given the plain brief and nothing about `sv`, with
`sv mcp` attached for the one run, in a fresh folder under the home folder; two builds with Sonnet 5.5 and four with
Haiku 4.5, each then checked with `sv report --run`. $1.86 of the owner's API credit in all.

**Results.** Every build used `sv` before writing code, unasked: the specification, then guidance, `before`, or the
plan. The first two Haiku builds did what the server says, settling the design with the owner, and stopped to ask; a
headless build has no owner, so the request gained one sentence saying the owner is away (amendment 1), and the
two built with it recorded their decisions with `securevibe_record_answer` instead. All four builds that wrote an app
started and could be signed in to: 34 and 38 checks answered for Sonnet, 21 and 27 for Haiku. Three builds ran
`sv check`, once each, at the end; the check, fix, and check again that the loop is for was not seen.

**What it found in `sv`.** The plan is too big for the tool to pass on whole (115,618 characters); a manifest error
names the field and not the section, and one build sent the same mistake five times; and `sv check` is silent on a
committable `.env` until the folder is a git repository. Each is in the backlog.

**How the key was kept.** The program had no sign-in from a terminal, and the owner chose API credit (amendment 2).
The key reaches only the Claude program, through an `apiKeyHelper`, never the environment of the builder's shell, the
app, or `sv`, and no transcript holds it.
