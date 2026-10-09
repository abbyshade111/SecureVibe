# The dashboard's history counts a run it cannot read (9 October 2026)

Backlog 226 (the observability review), part 1, item 8, built by session stackvet-e9.

**What was wrong.** `runs_in` (`crates/sv-cli/src/history.rs`) passed over any kept file that did not parse as a
`Run`, and `Run` (`crates/sv-report/src/dashboard.rs`) had no defaults. So the first field added to `Run` would have
made every run kept before it fail to parse, and the dashboard's "Over time" would have shown nothing about the
earlier runs, and nothing to say they were missing. A file changed by hand vanished the same way.

**What changed.** `Run` has `#[serde(default)]`, so a run missing a later field reads with that field empty. A file
with no `format` (`{}`, or any JSON that is not a run) is not a run, and neither is one that does not parse; both are
counted. `history::runs` returns the runs and that count, `App` carries it as `unread_runs`, and "Over time" says
"One file in this app's history could not be read as a run, and is not shown" (or how many), even when no run could
be read. `docs/DASHBOARD.md`'s "Keeping history safely" says so. Pruning to the hundred newest still counts only
runs that read, so an unreadable file is never deleted by `sv`; `sv history forget` removes it with the rest.

**Tests.** `history/unread_tests.rs` keeps a whole run, one missing `not_run`, one that is not JSON, and `{}`: both
runs read, in order, and two are counted. `dashboard/unread_tests.rs` checks the page's sentence for one and for
several, and its absence when there are none. Breaks: without the defaults the older run vanished; with the count
never raised the test caught the silent pass; with the sentence never written, the page test failed.
