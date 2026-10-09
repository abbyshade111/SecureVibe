# Why the level, and on whose word (9 October 2026)

The gap analysis of 7 October 2026, finding 17, its first part. An app's ASVS level is set by two answers in
`stackvet.toml`: who uses it (`audience`) and what it holds about people (`[data] categories`). The AI coding tool
usually writes that file, `sv review` seals neither answer, and the report said only "Held to ASVS level 1." A level 1
resting on the tool's `audience = "just-me"` read the same as one the owner had thought about.

**What the report says now**, after the level line, on the report page, both Markdown files, and the opening summary:

- why: "Level 1 because stackvet.toml says only you use it, and that the app holds nothing sensitive about people", or
  for level 2 the answer or answers that made it so: customers or the public use it, sensitive information is listed
  (named), the data list was left unanswered, or a name on it is not one `sv` knows;
- on whose word: "answers in stackvet.toml, which your AI coding tool usually writes and nobody has confirmed, so
  check them";
- at level 1, what level 2 would add: "At level 2, 98 more requirements would apply", counting level 2's own
  requirements and not level 3's.

`report.json` carries the same as `level_why` (`because`, `level_two_more`). A report built without a manifest's
answers, as many tests build one, says nothing more than before. The level, and what applies at it, are unchanged.

**Held by** `crates/sv-manifest/tests/level_because.rs` (eight combinations of audience and data, each with its level
and its words) and `crates/sv-cli/tests/level_why.rs` (through the binary: level 1 with its count, which must be more
than nothing and less than everything above level 1, and level 2 for the audience and for an unanswered list, with no
"at level 2" line). Broken two ways: the reason never set on the report (both tests failed), and every requirement
above level 1 counted instead of level 2's (the count test failed).

**Still open from finding 17:** `sv review` sealing the scope, and showing the level 2 count only until it is sealed;
comparing `audience = "just-me"` with a public sign-up page, and a health-like app with `categories = []`.
