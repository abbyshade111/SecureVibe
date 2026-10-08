# Limits on what the app may use (4 October 2026)

The deep review of `sv` at `eff3f17` found that the app ran with no limit on memory, processes, or processors, and
that `sv` kept everything a command printed (S9, medium). The app is code `sv` was asked to check, not code it trusts:
one that leaks memory, starts processes without end, or answers a request with gigabytes could take the owner's
computer down with it. Recorded under ADR-019.

- **Every container is limited, in one place.** `DockerBackend::prepared` is the one place every `docker run` and
  `docker create` passes through, where they are already labeled for cleanup, and it adds the limits there: 2 GB of
  memory with no swap beyond it, 512 processes, and two processors. When Docker has fewer than two it gets all of
  them, since Docker refuses to start a container asking for more than it has, and when Docker will not say how many
  it has, no processor limit is set and the others still are. A helper added later cannot be missed. The app's
  in-memory folders count against its memory, and the browser's and the mail server's now have a size, as the app's
  did.
- **`sv` keeps at most 32 MB of what a command prints**, on each of its two streams. The rest is still read, and
  thrown away, so the command never waits on a full pipe. Output that was cut ends with a line saying so.
- **A cut answer is never judged.** Every Docker call ends in `finished`, which refuses output that was cut, so a
  check never reads the first 32 MB of a page as the whole of it; the check reports that it could not ask. A test
  suite's own output is shown cut, with the line, and its exit code still counts.
- **Not `--user`.** The review asked for that too. With every capability dropped and `no-new-privileges`, root in the
  container cannot read others' files, change ownership, or gain anything back, while a fixed other user would stop
  many images from starting at all (ADR-019).

How it is held: `every_container_is_started_with_limits_and_nothing_else_is_changed` and
`the_processor_limit_never_asks_for_more_than_docker_has` (`crates/sv-run/src/docker.rs`), and
`output_past_the_limit_is_read_and_not_kept` (`crates/sv-run/src/lib.rs`). Each guard was undone in turn and its
test went red: the limits, the size of the browser's folder, the processor count, the cap, and the refusal of cut
output.
