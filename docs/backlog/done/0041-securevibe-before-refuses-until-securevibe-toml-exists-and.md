# `securevibe_before` refuses until `securevibe.toml` exists, and builders ask for it first

**Status:** done, as its markers read on 8 October 2026

Found on 6 October
2026 by session paper-facts, in the delivery test: with the specification in the request, most builders asked for
the feature briefs before writing the file, were told to write it and check again, and few asked again; the AI
brief, which carries the AI-feature prompt, reached 2 of 10 Sonnet and 3 of 10 Haiku builds. A brief could answer
without the file: what a feature brings, its decisions, the prompts shown to work, and the settings `sv run` needs
are the same for every app, and only "which of them apply now" needs the file. Say that part is waiting, and give
the rest.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
backlog when ready"), in branch `claude/securevibe-e2-brief-before-toml`: with no `securevibe.toml`, the brief
(`securevibe_before` and `sv brief`) gives what the feature can bring at every level, its decisions, the prompts shown
to work, its coding rules, and the settings, and says that which requirements apply, and the tests to write, wait
for the file. Read on `main` just before this claim: no other session had claimed it.
**Done the same day** (DESIGN, "A feature brief before securevibe.toml"): with no `securevibe.toml`, `securevibe_before`
and `sv brief` give every requirement the feature can bring at every level, its decisions, the prompts shown to work
for those requirements, its coding rules, and its settings, and say that which apply, and the tests, wait for the
file; the structured result says so in `waiting`. No check is started for it. Seven guards broken in turn, each
caught. Whether more builders then get the AI prompt is for the next delivery trial to measure.
