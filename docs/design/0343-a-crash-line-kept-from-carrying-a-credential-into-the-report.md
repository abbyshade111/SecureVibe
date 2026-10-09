# A crash line kept from carrying a credential into the report (9 October 2026)


Backlog 0226, part 1, item 1 (the observability review of 9 October 2026).

**The problem.** When the app cannot be run, the reason quotes what it printed: its crash line or last line
(`never_ready_detail`), the end of a failed install (`install_failure`), what the container backend said. That text is
the app's, not `sv`'s, and it went into the report's note about the run, its gap, and the terminal word for word. A
database error that prints its address prints the password in it. `sv bundle` refused to zip such a report, but the
files on disk kept the value, against the rule that `sv` never writes a key into a report.

**What is done.** Every way out of `probe_the_running_app` (`crates/sv-cli/src/lib.rs`), the one function `sv run` and
`sv report --run` share, now passes through `cannot_run_said`, which cuts every credential as a finding shows one
(`secrets::redact_text`: the rules' keys, a value given to a credential's name, a token after `Bearer`, a password in
a web address). It is one place on purpose: it covers every kind of failure, including ones added later, the report
and the terminal alike. When `sv`'s own rules cannot be read, nothing can be cut, so the app's words are left out
whole and the reason says only what kind of failure it was (`CannotRun::kind`, new in `crates/sv-run/src/lib.rs`).

**Tested, and broken.** `crates/sv-cli/src/cannot_run_said_tests.rs` plants a key and a database address with its
password, built from pieces, in each failure that quotes the app (it never answered, the install failed, the backend
refused, the install was refused), asserts first that the reason as `sv-run` states it really carries both, then that
neither survives while the error's name does. Passing the reason through whole failed two tests; handing the run's
outcome on without the function, at its one call site, failed the test that reads the function's source, there because
the run's own failures need a container backend to happen and the unit tests have none.

**And the seed.** A failed `seed` command's first line reached the report by another road, as the reason the signed-in
checks were not assessed (`seed_failed` in `crates/sv-run/src/docker.rs`), with only `sv`'s own test secrets taken
out by value. It is now cut the same way after them: `sv`'s secrets become a blank the redaction leaves alone, every
other credential is cut, and the blank reads "[a test secret, left out]" as before. Without the rules, the line is
left out. `crates/sv-run/src/seed_failure_tests.rs` plants the app's own key and database password; passing the line
through whole failed exactly that test, and the older test for `sv`'s own secrets still passes.
