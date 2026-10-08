# A check that asked says what it found (8 October 2026)



From the architecture assessment of 8 October 2026, item 8, its fuller form
(`docs/backlog/0187-from-the-architecture-assessment-of-8-october-2026-the-four.md`). A check of the signed-in suite
is `fn(.., out: &mut Outcome)`, and nothing made it touch `out`: four checks returned without a word, found by hand
that day, and `asked_tests.rs` now holds the suite as a whole to naming what the correct app's run names. Nothing
held each check.

**What was measured first.** Each of the 46 check calls in `run_checks` was wrapped in a recorder, and sv-check's
whole test suite run (4,300 runs of the suite against the fake app). Two things the assessment assumed did not hold.
Most checks say nothing at all when their part of `securevibe.toml` is not set (`open_redirect_check` was silent in
4,302 of 4,305 runs), which is right: the report already says what nothing spoke to. And a check that speaks often
names only some of its requirements, since one of its rules may need a setting the run lacks, so "every requirement,
every time" would be wrong. What did hold: 29 checks never asked the app anything and then named none of their
requirements, and a thirtieth did so once, a fault (below). The other 16 do, as their answer: their rules are findings only, or they credit only what they can
show, so saying nothing means nothing was found.

**The guard.** Each of the 30 is called through `asked!`, with the requirements it speaks to. A connection wrapper
(`Counted`) counts what is asked of the app (requests, requests sent together, pages a browser opens; not the mock
provider or the mailbox). When a check asked anything and named none of its requirements, they are recorded as not
assessed, "asked and never answered", naming the check, so a silent return cannot leave them out of a report; and sv-check's own tests, against the fake app, stop there, so
the check is fixed rather than covered for. The 16 are called
through `quiet!`, which marks them as checks whose silence is an answer, and a test reads `run_checks` and fails on
a check called through neither.

**What it found.** One silent return: `archive_checks`, when `securevibe.toml` says the app unpacks only gzip and
states only `max-files`, signed in, sent nothing (a gzip holds one file, so the limit cannot be passed), and said
nothing about V5.2.3. Its test asserted the silence. It now says V5.2.3 is not assessed and what would settle it
(`max-unpacked-bytes`), and the test holds that.

Not done: the guard cannot see inside the 16 quiet checks, and the lists of requirements are written beside the
calls, not read from the rules, so a check that gains a rule needs its list extended (a requirement it names beyond
its list does not trip the guard).

**What CI found.** The first version stopped any debug build there. The workspace's tests build `sv` in debug and, in
CI, run it against real apps in Docker; that run failed twice at its tests while every test passed here, with no
Docker, and its log could not be read from the session. The likeliest reading is that a real app made a check fall
silent that the fake app never does. The stop is now `cfg!(test)`: sv-check's own tests, where every path is known.
A real run, debug or release, records the requirements as "asked and never answered", naming the check, so which
check it was will be in the report of that run. Not confirmed: that this was the cause, until CI passes.

Tests: five in `crates/sv-check/src/signed_in/check_guard_tests.rs` (every check called is one kind or the other; a
check that names what it asked about, or asked nothing, is left alone; one that asked and named only another
requirement stops sv-check's own tests; the connection counts what is asked of the app and nothing else), and the archive
test's new assertion. Six guards broken in turn, each caught: the guard never firing (1 test), sends not counted (1),
what was named ignored (342), a check called bare (1), the archive silence put back (1), and the same with the
archive test's own assertion also removed, which the guard alone stops, naming the check and V5.2.3.
