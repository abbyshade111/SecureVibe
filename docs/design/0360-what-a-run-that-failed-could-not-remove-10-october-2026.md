# What a run that failed could not remove (10 October 2026)

Backlog 226 (the observability review), part 2, item 18's remainder, built by session securevibe-e2. The first part
of item 18 (`docs/design/0350-what-happened-to-the-container-the-true-wait-how-it-ended.md`) made a finished run say
what its teardown could not remove; a failed run still did not.

**The problem.** A run's teardown (`Teardown` in `crates/sv-run/src/docker.rs`) removes the run's containers and its
network. A run that finishes calls `finish`, which returns what Docker would not remove, and `sv run` and the report
say it with the commands to remove it by hand. A run that fails (the fence cannot be made, the install fails, the app
never answers) returns early, and the teardown runs as the guard is dropped: its answer went nowhere. So the run most
likely to leave something behind was the one that never said so.

**What was built.** The guard's drop keeps what it could not remove on the backend (`DockerBackend::left_behind`,
emptied as each run starts), and `run` hands it to the failure: `RunFailed::not_removed`. `RunFailed::explain`, which
the terminal and the report both use, now says why the run failed, then what it removed of an earlier run's, then
what it could not remove of its own, in the same sentence a finished run uses (`not_removed_sentence`, shared by the
two). Nothing is removed that was not before; this only stops dropping the answer.

**Tests.** `crates/sv-run/src/docker/container_record_tests.rs`, `a_run_that_fails_says_what_its_teardown_could_not_remove`:
a real `run` against a stand-in `docker` that refuses to make the network and cannot remove the run's container. The
failure is the backend's, its `not_removed` names the container with what Docker said, its explanation carries the
sentence and the command, and nothing is left kept for the next run.

**Broken on purpose, each put back:** the drop's answer not kept (1 red), the failure given an empty list (1 red), and
the sentence left out of the explanation (1 red). One test each, as there is one path: the finished run's sentence
has its own test from the first part.
