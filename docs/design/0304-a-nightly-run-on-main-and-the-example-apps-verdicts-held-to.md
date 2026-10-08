# A nightly run on main, and the example apps' verdicts held to a snapshot (8 October 2026)


Asked for by the owner on 8 October 2026 ("can you help me set up the nightly routine you proposed"), from the
end-of-day write-up. The write-up proposed a nightly routine that runs the full suite with a container backend, the
credit census, and the example apps re-scored, and compares the counts with the night before. Looking at what CI
already does changed the shape: `rust.yml` runs all of that on every commit to `main`, with Docker, for nothing.
What a nightly run adds is a run on a day nobody pushed, when the newest stable toolchain, the runner image, or
Docker Hub can have moved under the build; and what the comparison wanted is better held as a test that fails at
pull-request time than as a note the next morning.

**The nightly run** is a `schedule` trigger on `rust.yml`, 03:17 UTC daily, running the `test` and `image` jobs on
`main`; the `publish` job keeps its push-only condition. GitHub's failure mail is the note. No Claude routine was
made, since it would spend tokens nightly to repeat the mail; ADR-051 has the Later entry.

**The verdict snapshot** is `crates/sv-cli/tests/verdicts.rs`: `sv report` on each app under `examples/`, each
requirement's status held to `tests/verdicts/<app>.json`, with the differences named when one moves
(`notes-with-users: V2.1.1 was checked and is now not-verified`) and the way to accept a meant change
(`SV_UPDATE_VERDICTS=1`, and the snapshots committed with it, saying why). A new example app fails the test until
it has a snapshot. Only the static report is held, so the statuses that appear are the three a reading of the code
can reach today; the running-app and attested statuses would need a run, which this does not make. The test takes
about three seconds for the five apps, and the reports were shown to give the same statuses twice over before the
snapshots were written. Breaking it on purpose, one expected status changed, failed the test on that requirement by
name.
