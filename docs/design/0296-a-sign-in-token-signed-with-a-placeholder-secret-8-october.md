# A sign-in token signed with a placeholder secret (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.5; BACKLOG, item 13, its part (f)). AI-written apps often copy the
secret their tutorial used: jwt.io's `your-256-bit-secret`, `secret`, `changeme`, `keyboard cat`. A token signed with
one of those can be written by anybody, as any user. The signed-in checks already asked whether the app checks its
token's signature (V9.1.1), whether it takes `alg: none` (V9.1.2), and where it takes its key from (V9.1.3); none asked
whether the key itself was one anybody knows.

`probe.app-token-placeholder-key`, in `crates/sv-check/src/signed_in/tokens.rs`, takes the app's own sign-in token,
when it is a JWT signed with a shared secret (HS256, HS384, or HS512), and signs its first two parts with each of 45
placeholder secrets in turn, comparing the result with the token's signature. It runs offline, from the token alone,
and sends the app nothing; it runs even when no private page was shown, since it needs none. A match is a critical
finding citing V9.1.1, naming the secret only as `sv`'s secrets scan names a credential, by its first four characters
and its length. No match is never credit: a secret not on the list may still be guessed. A token signed with a key
pair (RS256, ES256, and the like) has no shared secret, and is left alone.

The fake app the signed-in tests use gained a switch, `jwt_placeholder_key`, that signs its tokens with jwt.io's
example secret, made from pieces so the test file holds no secret whole.

Tests: three in `tokens.rs`. The fake app with the switch is caught whichever way the token travels, with the secret
never written whole in the finding or the run's steps, and its other token checks still credited; the fake app with
its own key is checked (the step says so) and not reported or credited; HS384 and HS512 tokens are caught, and an
RS256 one is not checked. Six guards broken in turn, each caught: the check never called, jwt.io's example left off
the list, HS384 signed as HS256, the secret printed whole, key pairs checked too, and no match credited.
