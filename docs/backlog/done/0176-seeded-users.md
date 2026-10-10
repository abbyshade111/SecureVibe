# Seeded users

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026. `[stack.run.users]` in securevibe.toml says how
accounts are made (`seed`, run in the app's container with the accounts in its environment, or the
app's own `signup`), how to sign in and out, which pages are private or admin-only, and how one user
creates a record another must not read. `crates/sv-check/src/signed_in.rs` asks seven things as two
test users and an admin — private pages (V8.2.1), admin pages (V8.2.1), another user's records
(V8.2.2), a forged cross-site request (V3.5.1), a new session at sign-in (V7.2.4), sign-out ending it
(V7.4.1) and the session cookie's attributes (V3.3.2, V3.3.4) — and every one shows its own setup
worked first or reports not assessed. Anti-forgery tokens are read from hidden fields (quoted or not),
`<meta>` tags or cookies. Tested against a scripted app with each flaw switchable (every rule found by
at least two tests), and under Docker against `examples/notes-with-users`: the correct app has all
seven confirmed, and a copy with five flaws switched on had all five found. That run also found two
bugs in the suite, both fixed: unquoted attributes hid the token, and a sign-out the app refused was
reported as a sign-out that did not end the session. Left over: V3.3.1 (Secure) cannot be judged over
the fence's plain HTTP; input handling (V5, V1.2) still needs knowledge of the app's forms.
