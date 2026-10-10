# sv compare, and what history keeps from a later sv (10 October 2026)


Backlog 0230: the last of ADR-083, item C of the observability review's part 3 (backlog 0226). Built by session
securevibe-e2.

**The problem.** History shows a trend, but only when it is on, and only as far as the dashboard's twelve names.
Someone who changed one thing and wants to know what it did to the report, requirement by requirement, had no way to
ask, short of reading two `report.json` files side by side.

**What was built.** `sv compare OLDER [NEWER]` (`crates/sv-cli/src/compare.rs`). Each side is read from a report
folder, or from an app folder's `stackvet-report`; NEWER defaults to this folder's report. Each report's run is built
as history would keep it (`dashboard::Run`, through serde, every field defaulting), so the comparison rule is the
dashboard's own (`not_comparable_with`) and the requirements that moved are `moved_since`'s, listed in full. For each
one, what credited it or was found against it on one side and not the other, by the check, rule, or file it names:
"gained: checked by ast.sql-built-by-hand", "lost: answered in your notes security-notes.md". Then the findings that
came and went, and the counts. Said first, when true: that `sv` cannot show it wrote a report (`report_seal::proven`
does not hold for its folder), that the two reports name different apps, that the runs were not alike, or that an
older report did not record its inputs. It writes nothing.

**Decision 4.** Already held by history (every field defaults; files that do not read are counted). A test now holds
that a field a later `sv` adds is passed over, and that an outcome this `sv` does not know makes the record unread
rather than guessed.

**Tests.** `crates/sv-cli/src/compare/tests.rs` (6, on reports made in the test) and `crates/sv-cli/tests/compare.rs`
(1, through the real `sv` with a home of its own: two real reports of an app before and after a SECURITY.md is added;
the finding that went away named, nothing written, no warning for two sealed reports; a report changed after `sv`
wrote it still compared and said not to be shown as `sv`'s; the one-folder form; and a folder with no report refused).
`crates/sv-report/src/dashboard/unfinished_tests.rs` gains the later-record test.

**Broken on purpose, each put back:** the seal never checked (1 red, end to end), the warning for an unsealed report
left out (2 red), gained and lost not listed (2 red), runs that were not alike not said (1 red), findings that went
away not listed (2 red), and the one-folder form not reading this folder's report (1 red). A check that the seal
covered the very bytes read was written and taken out again: no test could show it doing anything `proven`, which reads
the files as they are, does not already do.
