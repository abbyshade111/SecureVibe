# One static stage for `sv check` and `sv report` (8 October 2026)

Item 3 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026"). `sv check` and `sv report` each ran the five scanners that read the app's files, and then `sv check` parted
from the report: no merging of one weakness reported twice on a line, no marks for test code, a folder the manifest
sets apart, or a bundled library, no reviews applied, and every finding counted toward the exit status. The report
counted the findings left after a person's reviews, so `sv check --fail-on attention` could fail a CI pipeline on a
finding the owner had set aside, and the AI coding tool reading the failure would rewrite the code until it stopped
(ADR-023, Later, 8 October 2026, which records the decision).

`crates/sv-cli/src/static_scan.rs` holds both halves. `StaticScan::read` is the reading, in the report's first six
stages, with what the manifest sets apart passed in (nothing, when `sv check` finds no `securevibe.toml`); its
`findings`, `passed`, `file_gaps`, and `examined` are what the two commands used to compute each for themselves.
`settle` is the counting: merged, marked, the decisions held to the running app and then the reviews applied, one
finding per line, with what the run looked at passed in so an entry that matches nothing can say whether its rule
looked. `sv report` passes everything it found (advisories, tools, the running app, the design answers) and its full
`examined` list; `sv check` passes the five scanners' findings and the five scanners' entries, and no decisions, since
no app ran. The terminal now says what was set aside through `sv review`, by whom and why, and which entries do not
count, as the report does.

Held by `sv_check_counts_what_sv_report_counts_on_the_same_folder` (`crates/sv-cli/tests/finding_review.rs`): both
commands exit 1 on a medium finding and both exit 0 once the owner sets it aside; the AI coding tool's own proposal
is listed as not counted. With `settle` taken out of `sv check` on purpose, that test fails. `sv check` loads the
whole of `sv`'s data now (`Loaded::load`) rather than the two rule files alone, which costs it the frameworks' read
on every run; nothing it prints about files, coverage, or gaps changed, and the exit-code tests of 4 October pass as
they were.
