# A finding outranked by `sv`'s own run, and one about a requirement the app is not held to (6 October 2026)

Decided by the owner on 6 October 2026 (ADR-023, Later). Two of the owner's builds showed what `sv` let decide a
report: a Django rule's 43 findings on a Flask app outweighed `sv`'s own check of the running app, which had verified
V3.5.1 in the same run; and a finding about V1.3.12, above an Express app's level, was listed among those that count,
so the AI coding tool rewrote working code for it.

`sv_report::mark_outranked`, at the start of `build`, sets `Finding::outranked`:
- **`CheckedWhileRunning { check }`** for an outside tool's finding whose every applicable requirement a `probe.`
  check verified in this run, unless the requirement is one no check can settle. `Finding::withholds_credit` is then
  false, so the requirement is credited, and the finding is listed under "only worth a look", beside Semgrep's five
  usually wrong rules. A finding of `sv`'s own, one `sv`'s rule also reported, and one sharing its line with `sv`'s
  own are never outranked.
- **`NotHeldTo`** for a finding whose every requirement is outside the applicable set. It is listed in a group of its
  own, "about requirements this app is not held to", with a note to change the code for it only to meet that
  requirement too. A finding about no requirement stays with the app's own.

Each is listed apart (`Finding::apart`), shown in full, and marked in SARIF (`outrankedBy`, `notHeldTo`), `report.json`,
and the MCP server's schema. The exit status counts them as it did.

How it is held: two report tests with seven controls between them (`sv`'s own rule, a requirement only a check that
did not watch the app satisfied, two requirements of which the run verified one, a requirement no check can settle,
`sv`'s rule merged in, `sv`'s finding on the same line, a finding about an applicable requirement too, and one about
none), and a schema test for both kinds. Sixteen guards were undone in turn, each caught, and the schema entry's
removal was caught too.
