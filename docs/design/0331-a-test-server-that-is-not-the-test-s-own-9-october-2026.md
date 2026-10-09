# A test server that is not the test's own (9 October 2026)

Found chasing the intermittent `test` failures on `main` and on #1205 the same morning: "Connection reset by peer" in
`crates/sv-run/tests/model_provider_gemini.rs`, about once in forty runs of its test binary on unchanged code.

**What happened.** The three Node harnesses (`model_provider.rs`, `model_provider_gemini.rs`, `oidc_provider.rs`) pick a
port by binding to port 0, letting it go, and starting Node on it, then wait for `GET /_sv/health` to answer
`"ok":true`. Two tests in one binary run at once. Two things could go wrong:

- both could be handed the same port before either server bound it; the second server then failed to start, its health
  check reached the first test's server and passed, and that test talked to a server that was not its own until the
  other test ended and killed it;
- a health check made while a server was starting or stopping on that port panicked on a reset connection, though it
  only meant "not this one yet".

**What changed.** Both test servers (`model-provider.mjs`, `oidc-provider.mjs`) say which process they are in their
health answer (`"pid": …`), and each harness waits for the answer from the process it started. The start-up probe is a
function of its own that reads any failed connection as "not yet" rather than failing the test. A server that cannot
start is seen to exit, and the harness tries another port, as before. The health answer still says `"ok": true`, which
is all `sv run` reads of it.

**Held by** repetition: `cargo test -p sv-run --test model_provider_gemini` passed 80 runs of 80, against one failure
in about forty before. With only the process id checked, it still failed once in forty: the start-up probe was the
second fault.
