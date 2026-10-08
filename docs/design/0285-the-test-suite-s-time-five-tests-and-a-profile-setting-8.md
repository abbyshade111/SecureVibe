# The test suite's time: five tests and a profile setting (8 October 2026)

The architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October 2026", item 1)
timed the `sv-check` unit binary one test at a time: its 1,263 tests took 1,263 s single-threaded, 531 s on four
CPUs, of the whole suite's 896 s. The time was in five tests and a build setting. `a_crash_never_turns_a_finding_into_a_pass`
took 405 s, since each scenario's sweep runs the whole signed-in suite once per request it crashes; four
`signed_in::once` tests took 60 s each, since each ran the whole suite to reach one check; and the 46 `ast` tests took
126 s, since each case loaded the rules anew and compiled every query again, in a debug build of tree-sitter.

Four changes, none to what `sv` does:

- **Dependencies optimized in a debug build.** `[profile.dev.package."*"] opt-level = 2` in the workspace `Cargo.toml`:
  tree-sitter's parse tables, the regular expressions, and the hashing live in dependencies that never change between
  test runs, and `sv`'s own crates stay unoptimized and debuggable. The first build of the dependencies takes longer
  (about three minutes here); every build after it is as before.
- **The rules loaded once per test binary** (`ast::tests::rules`, a `OnceLock`): the queries compile the first time a
  test needs them and are kept.
- **The `once` tests call `once_check` itself**, against a fake app holding the two accounts, rather than the whole
  suite; the suite's own scenario tests still run it in its place.
- **One CI run per pull-request commit.** `rust.yml` ran on every push and on every pull request, so a commit on a
  pull-request branch ran the 15-minute test job twice, and branch protection waited for both. The `push` trigger is
  now `main` only (ADR-051 unchanged: every pull-request commit and every commit on `main` is still tested).

Measured here, four CPUs:

| Tests | Before | After |
|---|---|---|
| The 46 `ast` tests | 126 s | 1.9 s |
| The five crash-sweep tests | about 400 s on the critical path | 80 s |
| The `sv-check` unit binary, 1,269 tests | 531 s | 92 s |

The crash sweep is not changed: its scenarios already run on scoped threads, and the profile setting is what made each
of the suite runs it needs cheaper. Not done: splitting the sweep across scenarios as well, which on four CPUs would
gain little.
