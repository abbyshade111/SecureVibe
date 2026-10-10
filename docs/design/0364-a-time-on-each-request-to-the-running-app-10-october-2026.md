# A time on each request to the running app (10 October 2026)

Backlog 226 (the observability review), part 2, item 13, its last part, built by session stackvet-e9. Session
securevibe-e2 timed each suite (`docs/design/0362-a-time-on-each-running-app-suite-10-october-2026.md`) and left this
open: a time on each request inside a suite. Each suite's steps are strings, so a time on each would have meant
every suite timing itself.

**Taken where every request is sent.** No suite times itself. Every request to the running app goes out through
`DockerBackend::probe`, or `probe_in_turn` and `probe_together` for several in one call. Each now writes down how
long the call took, whether or not an answer came back: a request that failed took that long too. A request sent
alone is named by its id. Several in one call are one entry, named by the first and how many more, and how they
were sent ("auth-a-1 and 9 more, sent together"), since they shared the one call. The times are emptied at the start
of each run and handed back on `RunOutcome::request_timings`.

**In the report.** `report.json`'s `timings` lists them after the suites, as "the request …"
(`sv_report::REQUEST_TIMING`). Like a suite's, a request's time is counted in no total. Unlike a suite's, it is not
named among the slowest five, where it would stand beside the suite that holds it. A program reading `timings` has
every one.

**Tests.** `each_request_is_timed_where_it_is_sent_even_one_that_fails` in
`crates/sv-run/src/docker/container_record_tests.rs` uses a fake `docker` that waits and fails.
`each_request_follows_the_suites_named_as_a_request` is in `crates/sv-cli/src/assemble/timing_tests.rs`.
`a_request_is_neither_named_among_the_slowest_nor_counted_in_the_total` is in `crates/sv-report/src/timing_tests.rs`.
With each piece undone, its test fails.
