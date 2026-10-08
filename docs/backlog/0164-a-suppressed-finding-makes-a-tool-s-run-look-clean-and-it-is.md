# A suppressed finding makes a tool's run look clean, and it is credited

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September
2026 by session securevibe-e8: bandit and gosec are made to report what they were told to skip, every
suppressed result is shown and says so, and what cannot be shown withholds the clean-run credit.
`docs/DESIGN.md`, "A tool told to look away, corrected again". What was found: `# nosec` on a line makes bandit report nothing
about it, so `sv` sees an empty findings list, calls the run clean, and credits every requirement
that adapter's rules map to — including V1.2.4 for a file whose `search()` concatenates user input
straight into SQL. Verified by running bandit, not reasoned about:

    def search(db, q):
        return db.execute("select * from notes where t = '" + q + "'").fetchall()  # nosec

Bandit's SARIF for that file holds `"results": []` and, in `runs[0].properties.metrics._totals`,
`"nosec": 1` and `"skipped_tests": 0`. So the tool says plainly that it was told to look away, and
nothing reads it: `grep -rn nosec crates/ data/` finds nothing at all.

This is the missing-tool rule again, one layer in. A tool that is not installed already reports
*not run* rather than a clean pass, because absent must never read as clean; a tool that ran with
its mouth taped shut over the one line that matters is the same thing in a better disguise, and it
is worse, because the report says an automated check looked.

The fix is cheap for bandit, since the count is already in the report: read
`metrics._totals.nosec` and `skipped_tests`, and where either is non-zero say how many suppressions
there were and withhold that adapter's clean-run credit. gosec's `#nosec` and semgrep's
`// nosemgrep` need the same treatment and neither could be checked here — gosec is not installed,
and semgrep cannot start in this sandbox (`ca-certs: empty trust anchors`) — so what their reports
carry is unverified. If it turns out they say nothing about suppressions, the honest interim is to
count the markers in the files that were scanned.
