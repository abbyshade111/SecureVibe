# Say in `report.json` what was examined, in a form a program can read

**Status:** done, as its markers read on 8 October 2026

**Claimed on 28 September 2026 by
session cato-examined**, at the owner's asking.
`report.json` says what was not examined only in sentences: `gaps`, and the SARIF's `sv.not-examined`
notices. A program that reads it cannot tell a finding that was fixed from one nobody looked for this time.
The owner's cato-pipeline turns `sv` findings into a plan of action and closes an item when its finding stops
appearing, so a tool that did not run, a check that could not read what it needed, or code rules silenced by an
unparsed language would each close items that were never fixed. Plan: an `examined` list in `report.json`,
one entry per family of findings (a `rule_id` prefix: each outside tool, `sv`'s code rules, each check that could
not run, known vulnerabilities, the running app), each `ran` or `not-run` with the reason the gap already gives,
filled where those gaps are decided, and a test for each source that fails when its entry is wrong. Touches
`sv-report` (the field), `sv-cli` (filling it), and `docs/DESIGN.md`.
**Done on 28 September 2026 by session cato-examined:** `report.json` has `examined`, one entry per family
of findings with a state of `ran`, `partly`, `not-run`, or `nothing-to-examine`; the longest matching
`rules` prefix decides (DESIGN, "What was examined, for a program"). Five tests through the binary and three
beside the code; each of six guards, removed in turn, turns its test red. `design.`, `hand.`, and `tests.`
findings have no entry yet, so a program reads them as not looked for, which is the safe side.
