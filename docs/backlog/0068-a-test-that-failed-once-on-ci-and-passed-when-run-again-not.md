# A test that failed once on CI and passed when run again, not yet named

**Status:** done, as its markers read on 8 October 2026

Found on 28 September 2026 by
session securevibe-e9 on #344: the `test` job of the push run for `51c6d71` failed in the Tests step after
about three minutes ([run 36455276279](https://github.com/abbyshade111/SecureVibe/actions/runs/36455276279)),
while the pull-request run of the same code passed, main was green, and the whole workspace passed locally.
Run again once, it passed. The session could not read the log (its network policy refuses the download), so
which test failed is not known. **Not claimed.** A session that can read that run's log: name the test, find
why it depends on timing or on the machine, and make it deterministic. The Docker tests that race a timer
(`crates/sv-cli/tests/interrupt.rs`, `crates/sv-run/tests/limits.rs`) are the first suspects, as a guess.
**Claimed on 28 September 2026 by session securevibe-e2**, which read the log: the failing test is
`a_run_first_removes_what_a_stopped_run_left_on_this_machine_and_nothing_else` in
`crates/sv-run/tests/leftovers.rs` ("left was not started"), securevibe-e2's own.
**Done the same day.** The cause: the file's other test starts a real run, and every run begins by removing
what an ended process on this machine left, so it could remove the fake leftover the first test had just
made, before that test looked for it. On CI's slower machines the removal sometimes came in between.
Reproduced here with every processor kept busy (one failure in fifteen runs, the same message and line);
the two tests now take turns, and sixty runs under the same load all passed.
