# A token check that accepts the none algorithm (9 October 2026)


Finding 11 of the gap analysis of 7 October 2026, its last part (BACKLOG, "From the gap analysis of 7 October 2026"). A
token whose header says `alg: none` carries no signature. A check that accepts it lets anybody write a token naming
any user. The running check `probe.app-token-alg-none` sends one to the app, and Semgrep has rules for it. Plain
`sv check` had no rule of its own, so an app that `sv run` could not start was never asked.

**What changed.** A code rule, `ast.token-none-algorithm`, cites V9.1.2 and is only ever a finding. It reports a
token check whose list of accepted algorithms names `none`, in any case:

- PyJWT and python-jose: `algorithms=[...]`, or a tuple.
- Node's `jsonwebtoken`: `algorithms: [...]` in the options object.
- Go's `golang-jwt`: `jwt.WithValidMethods([]string{...})`, and a key function that returns
  `jwt.UnsafeAllowNoneSignatureType`.
- ruby-jwt: `algorithm:` or `algorithms:` in the options.

Not reported:

- A list without `none`.
- `none` given to anything other than the list of algorithms (an `audience`, a style's `display`, a status).
- A list built elsewhere and handed over by name.

**Why only ever a finding.** A list written out without `none` says nothing about one built elsewhere, so finding none
credits nothing. The running probe and Semgrep are what can show V9.1.2 holds.

**Languages not read.** Each says why:

- Rust's `jsonwebtoken` has no `none` to accept.
- C#, Java, and Kotlin are not looked at yet. Their switch for an unchecked signature is read by
  `ast.token-signature-not-checked`.
- In PHP, `firebase/php-jwt` takes no `none`, and `lcobucci/jwt`'s `None` signer is not looked for yet.
- No way to accept `none` is known for the common token libraries of Dart, Swift, C, and C++.

**Tests.** `crates/sv-check/src/ast/token_none_tests.rs` has a case to find and one to leave in each language. Breaking
the guard four ways turned that language's test red each time:

- loosening Python's check of the list;
- dropping Go's `UnsafeAllowNoneSignatureType` form;
- renaming JavaScript's key;
- narrowing Ruby's keys.
