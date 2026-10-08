# A `securevibe.toml` field in the wrong section: the message names the field, not the section

**Status:** done, as its markers read on 8 October 2026

Found on 5 October
2026 by session paper-facts, in the loop pilot. Haiku 4.5 wrote `enabled = true` under `[stack.run.ai]`; `sv`
answered with the line, the field, and the fields allowed, and the builder sent the same mistake back five times,
rewriting the file twice, before it put the field where it belongs. Naming the section the line was read in (`in [stack.run.ai]`) would say where
it went wrong.
**Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking to take another of the
pilot's findings, in branch `claude/manifest-section-in-message`.
**Done the same day** (DESIGN, "A misplaced field names its section"): every message `sv` gives for an unknown
field in securevibe.toml now names the section the line was read in (`[stack.run.ai]`, `[[finding-review]] number
2`, `[design."V6.2.1"]`, or the top level), and the sections where a field of that name belongs, found by walking
the manifest's own types, so the list cannot fall behind them: the pilot's line is answered "`enabled` is not a
field of [stack.run.ai]. Did you mean [capabilities.ai]?" The line, its pointer, and the fields allowed are kept.
One place (`Manifest::parse`) serves `sv scope`, `report`, `audit`, `rules`, `plan`, `run`, and every MCP tool.
Tested on the pilot's case, a field two other sections take, one none takes, a deep section, an inline table, two
arrays of tables, a keyed section, the top level, and a value of the wrong kind, and through the binary and the MCP
server; with the new message taken out, all eleven went red, and each smaller break was caught.
