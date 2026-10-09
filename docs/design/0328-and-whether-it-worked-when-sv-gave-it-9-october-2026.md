# And whether it worked when sv gave it (9 October 2026)

The second half of the gap analysis's finding 22(g) (7 October 2026); the first half, "And on how many builds", said
how many builds each prompt was shown on. "Shown to work" still read the same for a prompt pasted into the request
and for one `sv` gave the AI tool itself, and the two are not the same: `ai-feature-guard` removed all three of its
problems when pasted, and when `sv` gave it, hidden characters still reached the page in 9 of 10 builds.

Each prompt's trial record now carries `delivered`: one reading for each trial and model of the two trials in which
`sv` gave the prompts itself (`docs/prompts/library-trial/start.md`, at the start of every build, and `delivery.md`,
in the feature briefs and guidance), each "works", "not shown", or "no reading" (fewer than half the builds without
it had the problem). Every copy of a prompt's status (`sv prompts`, the MCP server's prompts and offers, the feature
briefs, the plan, the instructions the AI tool reads first) adds a sentence from them:

- `secrets-in-the-environment`: "Given by `sv` rather than pasted into the request: at the start of a build, shown to
  work with Sonnet, no reading with Haiku; in its briefs and guidance, not shown to work with Sonnet and Haiku."
- `ai-feature-guard`: not shown to work with Sonnet, both ways.
- `security-headers` and `private-pages-no-store`: no reading, but for Haiku in the briefs (not shown).
- Every other prompt shown to work: "Given by `sv` rather than pasted into the request, it has not been tried."

A prompt not shown to work, with no reading, says nothing more. Which prompts count as shown, and so which `sv`
gives (ADR-044), is unchanged.

Held by `crates/sv-check/tests/prompts_delivered.rs`: the readings equal, exactly, those in each trial's verdict
file (`start-verdicts.json`, `delivery-verdicts.json`), and the sentence is held for both kinds and for a shown
prompt with none. Broken two ways: one reading changed in `data/prompts.json` (both tests failed), and the sentence
left out (the wording test failed).
