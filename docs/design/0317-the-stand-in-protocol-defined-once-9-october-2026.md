# The stand-in protocol defined once (9 October 2026)



From the architecture assessment of 8 October 2026, item 9
(`docs/backlog/done/0187-from-the-architecture-assessment-of-8-october-2026-the-four.md`). `sv` runs two stand-ins inside
the fence, the test model (`crates/sv-run/assets/model-provider.mjs`) and the test sign-in provider
(`oidc-provider.mjs`). Each script is a server whose addresses, markers, and mode names are a protocol, and every Rust
client, the Docker runner, and every fake the tests use in a script's place wrote that protocol out again as its own
strings. Only the model's script was ever run by a test, so the sign-in provider could change under the Rust side
with nothing to notice: the fakes would go on agreeing with the Rust side and with each other.

**One place for the protocol.** `sv_check::stand_in` holds it: the health address, the test model's addresses
(`seen`, `fetch`, `redirect`, `fetched`, `keys`, the hidden link and the image address), the message marker
`SV-PROBE-<KIND>-<tag>` (`marker`), and the sign-in provider's mode address and the nine mode names
(`stand_in::oidc`, in the order the script lists them). `ai.rs`, `oidc.rs`, `fetch.rs`, the token checks, the Docker
runner's health wait, the fake app, and the AI fakes take them from there; none writes its own.

**The sign-in provider's script run by a test.** `crates/sv-run/tests/oidc_provider.rs` starts the real script under
Node, as `model_provider.rs` does for the model, and holds it to `stand_in`. Every mode name is taken and an unknown
one refused. A whole sign-in (to `/authorize`, then the code to `/token`) is made after each mode, and the ID token
checked for what the Rust side assumes the mode does: the nonce, the audience, the issuer in the token and on the
way back, the person and the address, no signature, and a signature that does not check against the published key
(asked of Node's own crypto, so the test needs no RSA library). The sign-in after each is checked to be ordinary
again, since a mode is used once. `model_provider.rs` now takes its addresses and markers from `stand_in` too, so the
model's script is held to the same names.

**Not done: the browser driver.** The assessment named the same split there (`browser.rs` against
`browser-driver.mjs`). On the Rust side its actions are already written in one place (`Action::to_json`); a test that
runs the driver needs a real browser in the test environment, which is more than this item. It stays open.

Nothing a run asks or concludes changes.

Tests: one new, `oidc_provider.rs`; the rest of sv-check's and sv-run's tests pass unchanged, the model's contract
test with its strings replaced. Eight guards broken in turn, each caught by a contract test: a mode renamed in the
script, the same mode renamed in `stand_in`, the wrong-key token signed with the real key, a mode not used up after
one token, the health address moved, the wrong-nonce token keeping the nonce, and the other person given the same
`sub` (each by `oidc_provider.rs`); and the model's `seen` address changed in `stand_in` (by `model_provider.rs`).
