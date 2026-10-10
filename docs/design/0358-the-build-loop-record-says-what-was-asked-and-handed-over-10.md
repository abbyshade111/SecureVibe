# The build-loop record says what was asked and handed over (10 October 2026)


Backlog 0231: ADR-084's decisions 3 and 5, the last of item D of the observability review's part 3 (backlog 0226).
Built by session securevibe-e2.

**The problem.** The record of the build loop said a tool was called, not what about, and said nothing of what `sv`
gave the AI coding tool: its instructions when it connected, the prompts it fetched, the report files it read. So the
report could not say whether the tool read the report and rules it was given.

**What was built.** `build_loop::Line` gains `asked` and `handed`, each at most 20 names, each checked when read back
(`is_name`, `is_handed`). The server keeps a value an AI tool sent only when it is one `sv` defines (`Server::asked`):
listed as allowed in that tool's own published schema, or a requirement id the frameworks hold. Its instructions at
`initialize` and a prompt fetched with `prompts/get` name no app, so the server keeps them (`hand_over`) and the next
line written for an app carries them; a report file read with `resources/read` is written down at once for the app the
report folder sits in (`report_read`). `summarize` keeps each name once, in the order first seen, and the paragraph says
what the tool asked about and what `sv` gave it (`handed_said`), never what it was not given.

**Tests.** `crates/sv-cli/src/build_loop/names_tests.rs` (3: what a name may be; asked and handed read back, and a
tool's words, a path, an unknown kind, or too many refused; each name once in order) and
`crates/sv-cli/src/mcp/build_loop_names_tests.rs` (1, through the server: connect, fetch the report prompt, ask about a
feature and a requirement, ask for guidance in the tool's own words, write a report, read `report.html`, and the next
report saying exactly what was asked and handed over, with the tool's own words nowhere in the record).

**Broken on purpose, each put back:** any value kept (1 red), the schema's list not read (1 red), a requirement id not
looked up (1 red), the instructions not handed over (1 red), a prompt not handed over (1 red), a report read not
written down (1 red), what was handed over carried on every line (1 red), a tool's words accepted as a name (2 red),
any kind of hand-over accepted (1 red), and none of it said (1 red).

**With this, ADR-084 is built in full** (decisions 1, 2, 4: `0356`; decision 6: `0357`; decisions 3 and 5: here).
