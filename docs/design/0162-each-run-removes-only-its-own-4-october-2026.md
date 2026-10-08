# Each run removes only its own (4 October 2026)

S10 of the deep review: a run was named `sv-<process id>-<number>`, and its teardown removed containers by those
names. Two copies of `sv`, each in its own container and each process 7 there, sharing one Docker daemon, named
their runs alike, so either run's teardown could remove the other's app halfway through its checks. Recorded under
ADR-019.

- **A random part in every name.** `run_id` adds four bytes from the system's randomness: `sv-7-0-0badc0de`.
- **A label on everything a run creates.** While a run is under way, `DockerBackend::prepared` gives every
  `docker run`, `docker create`, and `docker network create` the label `org.securevibe.run=<the run's name>`, beside
  the owner label the crash cleanup reads.
- **The teardown removes what carries that label**, by id: `docker ps -aq` and `docker network ls -q`, filtered by
  the label. Only when Docker will not list them does it fall back to the run's own names, which hold the random
  part, so even then it cannot name another run's.

How it is held: `two_runs_never_share_a_name`, `everything_a_run_creates_carries_its_label_and_nothing_else_does`, and
`a_teardown_removes_what_docker_lists_under_its_label` (`crates/sv-run/src/docker.rs`). Four guards were undone in
turn, and each turned its test red.
