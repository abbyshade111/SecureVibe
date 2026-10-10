# What happened to the container: the true wait, how it ended, the fence, what was left, the kept volume (10 October 2026)

Backlog 226 (the observability review), part 2, item 18, built by session stackvet-e9.

**An app that stopped before it answered.** The wait for the health path gave up early when the app's container had
exited, and the message still said "never answered on its health path within 60s". `wait_until_ready` now returns
how long it waited and, when the app stopped of its own accord, its exit code and whether Docker killed it for
using more memory than it was given (`docker inspect`'s `OOMKilled`). `CannotRun::NeverReady` gains `exited`.
The message then says "The app stopped 2s after it started, with exit code 3", or that it was killed for memory,
in place of the wait it never had.

**What happened to the containers on a run that worked.** `RunOutcome` gains `container`, a `ContainerRecord`
that `sv run` prints after the fence and the report adds to its note on the run:

- how many seconds the app took to answer on its health path;
- how its fenced network was made, which was said only when the gateway check failed;
- what could not be removed when the run ended, each with Docker's words, and the commands that remove a
  container or a network. The helpers' removals and the teardown guard dropped every answer (`let _`). The guard
  gains `finish`, which removes and names what is left, and its `Drop` still covers an early return. A container
  or network that was already gone ("No such …") is not one left behind;
- the download volumes kept for the next run (ADR-052), with `docker volume rm` and the `stackvet.deps` label
  that lists them all.

ADR-052 named the old label, `securevibe.deps`; it now names `stackvet.deps` and says the run names the volumes it
kept.

Not built: what a run that failed could not remove. The failure path still drops the guard and says nothing of
what it left, since `RunFailed` holds only the reason and what was cleaned up first.

**Tests.** `crates/sv-run/src/docker/container_record_tests.rs`, unix only:

- a fake `docker` that cannot remove one container and finds another already gone, whose teardown names only the
  first;
- reading how a container ended from `docker inspect`;
- the message for an app that exited at once, and for one killed for memory;
- the record in sentences.

With the teardown's answer dropped again, or with the old wording, a test fails. No container backend was
available where this was built, so the path through a real run was not taken here.
