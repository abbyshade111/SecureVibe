# The smaller ones: a catalog not understood, report.json's format, and the advisory database named (10 October 2026)

Backlog 226 (the observability review), part 2, item 20, three of its four parts, built by session stackvet-e9.

**A version catalog that does not parse.** A Gradle build's `gradle/libs.versions.toml` that was there but was not
valid TOML read as missing: each `libs.…` dependency was unsettled because of "a version catalog `sv` did not
find". `find_catalog` (`crates/sv-scan/src/jvm.rs`) now tells the two apart, and the reason reads "`gradle/libs.
versions.toml` was not understood: it is not valid TOML" (or "it is not text"). The catalog is also named among the
package lists `sv` could not read (`deps::unread_in`, from #1337), which the report's "What was not examined" and
`sv scope` already show.

**`report.json`'s format.** It carries `report_format`, now 1 (`sv_report::json::REPORT_FORMAT`). The number goes up
when a field is removed, renamed or changes what it means, and not when a field is added. A program reading a
report can then tell one it knows how to read from one a later `sv` wrote.

**The advisory database a report compared with.** Read in `assemble.rs`: a report named none of which database it
used, how many records it held, or how recent it was. A comparison against a database months old read the same as
one against today's. The `advisory.` entry in `examined` now carries `advisories`: the folder as given with
`--advisories`, the records `sv` read, and the day the newest was published. The top of `report.html` and
`compliance.md` says "The app's packages were compared with the advisory database in …: 2 records, the newest
published 2026-09-30. A vulnerability published after that is not in it."

Not built: requirement ids and a reason code on each gap. Gaps are still `Gap { what, why }` in prose, built in 69
places, and the reason codes need settling as a set first.

**Tests.**

- `a_catalog_that_does_not_parse_is_not_understood_rather_than_not_found` in `jvm.rs`.
- `a_version_catalog_that_does_not_parse_is_named_among_the_unread` in `crates/sv-scan/tests/unread_manifests.rs`.
- `the_report_names_the_database_it_compared_with_its_size_and_newest_record` in
  `crates/sv-cli/tests/report_advisories.rs`, through the real `sv`.

With each change undone, its test fails.
