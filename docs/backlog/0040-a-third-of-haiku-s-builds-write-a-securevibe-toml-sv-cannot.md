# A third of Haiku's builds write a `securevibe.toml` `sv` cannot read, without `sv` to tell them

**Status:** claimed by paper-facts, as its markers read on 8 October 2026

Found on 6
October 2026 by session paper-facts, in the prompt-library trial: 22 of 70 Haiku 4.5 builds given `sv init`'s
specification but no MCP server wrote a file `sv` refused, whatever their prompt: `enabled = true` under
`[stack.run.ai]` in 14 (the field belongs to `[capabilities.ai]`), `signup = false` in 2, and others. `sv`'s
message names the fix, but a builder working from the specification alone never sees it. Ways out: the
specification's `[stack.run.ai]` example says outright that it takes no `enabled`; `sv init` offers a way to check
a draft file without the rest of a report; or `sv` accepts `enabled` there and says it is ignored. Each would be
measured the same way: how many such builds' files `sv` can read.
**Claimed on 6 October 2026 by session paper-facts** with the item above (prompt delivery), for the
specification's wording only, in branch `claude/prompt-delivery`.
