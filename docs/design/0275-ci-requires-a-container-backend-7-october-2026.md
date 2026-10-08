# CI requires a container backend (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 7.2). Thirty-eight places in twelve test files print "no container
backend here" and take the honest-absence path, asserting that `sv` says the app was not assessed. That is the right
test on a computer without Docker, and the wrong one on CI, where GitHub's runners have Docker: if the runner's Docker
broke, every fence test would stay green while none of them ran the app.

One test, `a_container_backend_is_here_where_ci_says_it_must_be` (`crates/sv-run/tests/fence.rs`), fails when
`SV_REQUIRE_BACKEND=1` is set and no backend answers, naming why (`docker info` failing, or no `docker` to start);
without the variable it says a backend is not required and passes. `rust.yml` sets it for the test job (ADR-051,
"Later, 7 October 2026"). One test rather than thirty-eight changed branches, so the honest-absence paths stay as they
are for everyone else.

**What was verified where.** Both failing cases were run in this session's container, which has the `docker` program
and no running daemon, and with `docker` taken off the path: each failed, naming its reason. The passing case needs a
daemon, and is shown by the pull request's own CI run.
