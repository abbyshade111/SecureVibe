# More AST rules

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 — four more in `data/ast-rules.json`, nine in
all. `ast.file-path-from-value` (V5.3.2), `ast.weak-hash-function` (V11.4.1), `ast.weak-cipher`
(V11.3.1, V11.3.2) and `ast.open-redirect` (V3.7.2), across eight or nine languages each. Two new
fields made them possible without Rust per rule: `argumentPatterns` (the call is a finding only when
its argument says so — `createHash("md5")`, not `createHash("sha256")`) and `safeArgumentPatterns`
(named idioms that are not findings — `redirect(url_for(...))`, `secure_filename(...)`,
`path.join(__dirname, "a.html")`, a bare ALL-CAPS constant). A pattern for a language with no
query is refused at load. Every (rule, language) pair has a found and a not-found witness, and a
test fails if one is missing; breaking each filter in turn turned two to seven witnesses red.
Left over, each its own decision rather than a data entry:
- **Predictable randomness (V11.5.1) was not written.** `Math.random()` and `random.choice` are fine
  for shuffling a list and wrong for a reset code, and what decides it is where the value goes,
  which a single query cannot see. A rule without that would mostly report shuffles.
  **The owner's decision, 6 October 2026: not built**; V11.5.1 stays a requirement to check by hand
  ("I agree with all your recommendations", 6 October 2026).
- ~~Express's two-argument `res.redirect(301, url)`, Ruby's `send_file`, Java's `Paths.get`, and
  PHP's `include $x` are missed.~~ **Claimed on 26 September 2026 by session securevibe-e8. Done the
  same day**; see DESIGN, "Four ways of writing a path or a redirect that the rules missed". Ruby's
  `redirect_to` was already covered, and both rules now have queries in all fourteen languages,
  Kotlin, C, and Rust included, so the rest of this bullet was out of date.
- The file-path rule is low confidence on purpose: it cannot tell a request value from an internal
  one held in a lowercase variable.
