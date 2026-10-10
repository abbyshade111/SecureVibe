# History keeps each requirement's status, and names the ones that moved (10 October 2026)


Backlog 0230: ADR-083's decision 1, item C of the observability review's part 3 (backlog 0226), which the owner said
yes to on 9 October 2026. Built by session securevibe-e2.

**The problem.** History (ADR-057) kept each run's counts and findings. It could say "checked: 41 then, 40 now" but not
which requirement moved, so no trend could be drawn for one requirement and a dropped credit could not be named.

**What was built.** Each kept run (`dashboard::Run`, format 2) holds `requirements`: each applicable requirement's id
and status word, nothing of its text or the app's. `Run::moved_since` lists each requirement whose status differs
between two runs, including one that applied in only one of them, and `changes_since` names them on the page, the
first twelve by name and the rest counted. A record from before format 2 still reads (every field has a default), and
when it is set against a newer one with different counts, the page says which requirements moved is not known.

**Left for later in ADR-083:** a record for a failed run, more in the "can these runs be compared" key with the
reason named, and `sv compare`.

**Tests.** `crates/sv-report/src/dashboard/moved_tests.rs` (4) and `crates/sv-cli/tests/history_statuses.rs` (1,
through the real `sv` with a home of its own: the kept statuses are the report's, id and status only).

**Broken on purpose, each put back:** no statuses kept (1 red, the end-to-end test), a requirement that stopped
applying left unnamed (1 red), and the "not known" sentence left out (1 red).
