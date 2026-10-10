# History keeps a run that did not finish (10 October 2026)


Backlog 0230: ADR-083's decision 2, item C of the observability review's part 3 (backlog 0226). Built by session
securevibe-e2.

**The problem.** A run that failed or was stopped wrote no report and left no record, so the dashboard went on showing
the last report as if it were current, and nothing said a later run had been tried.

**What was built.** A kept run (`dashboard::Run`, format 4) says how it ended (`Outcome`: finished, failed, stopped) and
its exit code. `sv report` is now a wrapper around the command (`report_command`): once the app's folder is named, an
error keeps a failed run, and `exit::on_interrupt` sets the step `exit::exit_with` takes before it ends with 130, which
keeps a stopped one. `Run::unfinished` holds the start, `sv`'s version, the outcome, and the code; never the error's
words, which can quote the app's files, and never a name, so `history::keep` leaves the app's kept name as it was. The
page shows an unfinished run as "Did not finish: ...", never compares it, sets the next run against the last finished
one, and says above the report, in each app's view and in the view of every app, that the latest run did not finish
and which run the report is from (`unfinished_note`).

**Tests.** `crates/sv-report/src/dashboard/unfinished_tests.rs` (5) and `crates/sv-cli/tests/history_unfinished.rs`
(2, through the real `sv` with a home of its own: a run that failed on a `stackvet.toml` that does not read, after one
that finished, and the page made from them; and a real Ctrl-C during `sv report --tools`, as `tools_interrupt.rs`
sends it, which ends with 130 and leaves a stopped run).

**Broken on purpose, each put back:** the failed run not kept (1 red), no step before the Ctrl-C exit (1 red), an
unfinished run compared (3 red), the note that the report is older left out (2 red), a finished run's exit code not
kept (1 red), a failed run's empty name written over the app's (1 red), and the run before not skipping an unfinished
one (1 red).

**Left for later in ADR-083:** what remains of decision 4, and `sv compare`.
