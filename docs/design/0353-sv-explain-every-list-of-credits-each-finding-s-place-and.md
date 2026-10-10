# sv explain: every list of credits, each finding's place, and --report (10 October 2026)

Backlog 226 (the observability review), part 2, item 17, its `sv explain` half, built by session stackvet-e9. The
report half is the entry before.

**Every list of credits.** `sv explain ID --app DIR` printed only `checked_by`. It now prints each list a report row
holds, in a few words each: checked by, tested by the app's own tests (written by the AI coding tool, not a check
of `sv`'s), supporting it but not counted for it, answered in the security notes, checked by hand, and answered
yes. An entry from a person's word says whose it is when the report says so (`whose`). A row a set-aside false
alarm kept from *checked* says which and why (`withheld_by`).

**Each finding's place.** It said "2 findings name it; the report lists them". It now lists each with its rule, file
and line, and title. On a row that needs attention and that something passed for, it adds that a finding outranks
every credit, so what passed does not count.

**`--report FILE`.** It read only the app's last report. `--report` names another, such as one kept from an earlier
run. The same rule holds: only a report `sv` can show it wrote, sealed and unchanged, is repeated (part 1, item 9).
The output names the report it read: "In Notes's report at …/report.json, V9.1.2 is …".

**Tests.** `every_list_of_credits_is_given_with_whose_word_and_each_finding_with_its_place` in
`crates/sv-cli/src/explain/tests.rs`. `a_report_named_with_report_is_repeated_under_the_same_seal_rule` in
`crates/sv-cli/tests/explain_seal.rs`: a sealed copy elsewhere is repeated, and the same copy rewritten is left out.
With the lists cut to `checked_by`, no places, and `--report` ignored, both fail.
