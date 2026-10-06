# The delivery test, and the settings-file check: protocol, written before they run

Item 4 of the backlog's "Test the prompt library where the prompts have something to fix", and the re-test of the
specification's fix for unreadable settings files, at the owner's word of 6 October 2026. Fixed before any build; a
change made after a result is seen goes in "Amendments", dated, with its reason.

The builder, the request, the check, and the unusable-build rules are those of `protocol.md`: headless Claude Code
2.1.286 on the owner's API credit, the loop's plain brief with the owner-away sentence and `sv init`'s specification at
the top, `sv report --run` one build at a time. What differs is said below.

## Part A: does the specification's fix make settings files readable?

- **Builds:** 20, Claude Haiku 4.5, no MCP server and no prompt, with the specification of `sv` from the delivery
  branch (two sentences more: `[stack.run.ai]` takes no `enabled`; `signup` is a request, never true or false).
- **Measure:** of the builds that wrote a `securevibe.toml`, how many `sv` could read; and how many had `enabled`
  under `[stack.run.ai]` or `signup` set to true or false.
- **Compared with:** the prompt-library trial's 70 Haiku builds, whose files `sv` could not read in 22 (14 of them
  `enabled` under `[stack.run.ai]`, 2 `signup = false`).
- **Rule:** the fix **works** when at most 2 of the 20 have a file `sv` cannot read, and none has either of the two
  mistakes the sentences name. **Partly** when the two named mistakes are gone and the unreadable files are not.
  **Not shown** otherwise. Fisher's exact test is reported beside it.

## Part B: does `sv` deliver the prompts so that they work?

- **The change tested:** ADR-042. The brief for a feature (`securevibe_before`) gives the coding prompts shown to work
  for its requirements, and the guidance (`securevibe_guidance`) the rest of them, for the whole app.
- **Arms:** every MCP tool attached (the loop arm of the loop trials), with no prompt in the request.
  - **today's `sv`:** `a9d6fea4`, which gives none of the coding prompts in the brief or the guidance;
  - **delivering `sv`:** the delivery branch's build.
- **Models and size:** Claude Sonnet 5.5 and Claude Haiku 4.5, 10 builds an arm: 40 builds.
- **The prompts measured, and the check of each** (from the library): `ai-feature-guard` (Sonnet only, where its
  problem was common: the three `probe.ai-*` rules), `security-headers`, `private-pages-no-store`, and
  `secrets-in-the-environment` (both models).
- **Measures:**
  1. for each prompt, the share of builds with its problem, among those its check could be asked of (as in
     `protocol.md`); the arms differ in more than the delivery (the delivering `sv` also has Part A's sentences),
     so counts of builds asked are reported but only shares are compared;
  2. from the transcripts, whether the builder called the tool that carries each prompt (`securevibe_before` for the
     feature, `securevibe_guidance` with no topic), and so was given it;
  3. harm, as in `protocol.md`.
- **Rule, for each prompt and model:** delivery **works** when today's `sv` has the problem in at least half of the
  builds asked and the delivering `sv` in at most one in ten of those asked; **not shown** when today's has it in at
  least half and the delivering one in more; **no reading** when today's has it in fewer than half. A prompt that
  works when pasted (`protocol.md`) and not when delivered is reported with how many builders were given it.

## Cost

About $0.25 a build without the server and $0.40 with it: about $5 for Part A and $16 for Part B, $21 in all. Each
build is capped at $1.50: $90 at most. If Part A's first ten builds average more than $0.60, the run stops.

## Amendments

None yet.
