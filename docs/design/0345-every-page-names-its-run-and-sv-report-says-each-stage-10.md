# Every page names its run, and sv report says each stage (10 October 2026)

Backlog 226 (the observability review), part 2, items 12 and 15, built by session stackvet-e9.

**Every page names its run (item 12).** `sv report` left `generated` empty, so `report.html`, `compliance.md`,
`security.md`, and `findings.sarif` said nothing of when they were made; only `report.json` had `run_record`. The
run record now carries a run id, twelve hex digits from the start time to the millisecond, the process, and the
manifest's hash, so two runs at once differ. Each page's first line reads "Produced by `sv` … on
2026-10-10T00:01:02Z, run 1a2b3c4d5e6f", from the same record, so the pages and `report.json` agree. The SARIF's
invocation gains `startTimeUtc` and `properties.runId`. The clock is still read once, when the run starts, and the
report's renderers are still given the date rather than reading one, so their tests keep fixed text; `run_id` is
left out of a record without one.

**Each stage said (item 15).** `sv report` called the report builder with no word of its stages, which the MCP
server already passes on as progress, and `sv report --run --tools` then sat silent in "Putting the report together"
for minutes. That stage is now four: comparing the packages with known vulnerabilities, the outside tools, the
running app, and putting the report together, each named for when it runs, and every stage is still announced on
every run, so a count means the same each time (the MCP server's progress reads the same list, now ten long).
`sv report` prints "sv report: 8 of 10, Running the outside tools, when asked with --tools" on stderr as each
starts, at a terminal and in CI alike: CI logs had the same silence, and stdout is left as it was.

Not built: a line for each outside tool and each running-app suite within their stages, which needs a way for
`sv_check::adapters::run_all_in` and the running-app suites to say each start; left open on the item.

**Tests.** `crates/sv-cli/tests/dated_pages.rs` (two runs, two ids; each page names the run and start in
`report.json`; the SARIF the same) and `crates/sv-cli/tests/report_progress.rs` (the ten lines on stderr, in order,
none on stdout). Breaks: with `generated` left empty the first fails; with the stages unsaid the second does.
