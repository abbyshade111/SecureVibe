# A token read with its signature check switched off (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.3; BACKLOG, item 11, one of its rules). Plain `sv check`, with no
outside tool installed, had a rule for a token whose audience check is switched off (`ast.token-audience-not-checked`)
and none for the worse case beside it: a token whose signature is never checked, so anybody can write one naming any
user.

`ast.token-signature-not-checked`, in `data/ast-rules.json`, finds the explicit switches the common libraries have for
it: `verify_signature` false in PyJWT and python-jose, `JWT.decode` with its third argument `false` in ruby-jwt,
`RequireSignedTokens = false` in .NET, `insecure_disable_signature_validation()` and `dangerous_insecure_decode` in Rust's
`jsonwebtoken` (with or without a type given), `ParseUnverified` in Go's `golang-jwt`, and `unsecured()` in Java's
`jjwt`. High severity, citing V9.1.1, and only ever a finding: finding no switch does not show every token is checked.

JavaScript and TypeScript have no such switch: `jsonwebtoken`'s `jwt.decode` and `jose`'s `decodeJwt` read a token
without checking it, which is also how a browser reads its own token, so a call cannot be told from a fault in one file.
The rule says so for those languages rather than looking. The `none` algorithm (V9.1.2) and item 11's other rules stay
open.

Tests: twenty cases in the AST rules' table, each language's switch found and its checked form left alone, with
`requests.get(url, verify=False)` (a TLS setting, not a token) among the safe ones. Seven guards broken in turn, each
caught: Python's switch never matched, any `verify…` name counted, any `decode` counted in Ruby, `RequireSignedTokens =
true` counted, Rust's `decode::<Claims>(…)` form missed, any Go `Parse…` counted, and Java's switch never matched.
