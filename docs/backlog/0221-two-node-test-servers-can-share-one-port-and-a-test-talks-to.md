# Two Node test servers can share one port, and a test talks to the wrong one

**Status:** claimed by securevibe-e2, 9 October 2026

Found 9 October 2026 by session securevibe-e2, chasing the intermittent `test` failures on `main` (b64b2fe2) and on
#1205 that morning. The Node harnesses in `crates/sv-run/tests/` (`model_provider.rs`, `model_provider_gemini.rs`,
`oidc_provider.rs`) each pick a free port by binding to port 0 and letting it go, then start Node on it. Two tests in
one binary can be handed the same port before either server binds it; the second server then fails to start, its
health check reaches the first test's server and passes, and that test goes on talking to a server that is not its own,
until the first test ends and kills it: "Connection reset by peer". `model_provider_gemini` reproduced it about once
in forty runs of its binary on unchanged code, failing at the harness's start (`start`, then a later `call`).

The fix: each test server says which process it is in its health answer (`process.pid`), and the harnesses wait for
the answer from the process they started, so a test can never adopt another's server. A test-only change apart from
that one field of the health answer, so no record is proposed; ADR-019, ADR-042, ADR-064, and ADR-065 govern
`model-provider.mjs` and get "unchanged" lines.
