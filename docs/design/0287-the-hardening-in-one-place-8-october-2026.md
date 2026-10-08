# The hardening in one place (8 October 2026)

Every container `sv run` starts is read-only, with every capability dropped and no way to gain one (ADR-019). Until
8 October 2026 those five arguments were written out wherever a container was started: eleven places in
`crates/sv-run/src/docker.rs` and one in `install.rs`, and the fallback used when a sidecar cannot be started had once
been written without them, which the 4 October entry of ADR-019 records. The limits (memory, processes, processors)
had already been moved into `prepared`, the one function every Docker call passes through; the hardening now goes on
there too (`HARDENING`, `hardened`), for every `run` and `create` and never for an `exec` into a container already
running, and no builder carries a copy. The fallback path goes through `prepared` as well, so it also gets the limits
and the run label it lacked (the review of 8 October 2026, a low finding). What a container is started with is the
same; a path that forgets it can no longer be written.

The tests assert through `prepared`: each container kind's test (the app, the mail server, the test provider, the
test model, the browser and its driver, the fallback, and the install step's) shows the flags arrive exactly once and
that the builder wrote none of them, and one chokepoint test shows a plain `run` and `create` get them while an `exec`
does not. With the one place removed on purpose, seven tests failed.
