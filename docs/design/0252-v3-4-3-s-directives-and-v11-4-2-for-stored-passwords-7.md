# V3.4.3's directives, and V11.4.2 for stored passwords (7 October 2026)

Two citations the prompt-library review found (`docs/prompts/reviews/language-agnostic-variant.md`), settled by the
owner the same day.

**V3.4.3** (ASVS, level 2) asks for a Content-Security-Policy that "includes the directives object-src 'none' and
base-uri 'none' and defines either an allowlist or uses nonces or hashes". `probe.security-headers` and
`probe.private-page-headers` credited it for any policy at all, `frame-ancestors 'none'` alone included. The owner's
decision: "The check should look for them" (ADR-047). Both checks read one list of what a page lacks
(`missing_headers` in `crates/sv-check/src/probes.rs`), and a policy now adds to it what it is short of:

- `object-src 'none'`, or no `object-src` and `default-src 'none'`, which a browser reads the same way. A list with
  `'none'` and anything else is not `'none'`.
- `base-uri 'none'`. Nothing stands in for it: `base-uri` does not fall back to `default-src`.
- a `default-src` or a `script-src`, the allowlist. Nonces and hashes are written inside one of the two, so they need
  no case of their own.

Directive names and values are read without regard to capitals, as a browser reads them. A shortfall is named in the
finding with the other missing headers, and holds back the checks' credit for all four requirements together, as a
missing header always has.

**V11.4.2.** `ast.weak-password-key-derivation` (PBKDF2 with too few rounds) cited only V11.4.4, an encryption key made
from a password. Code that stores passwords is held to V11.4.2. The same call does both, and nothing in the code says
which, so the rule cites both and it is only ever a finding. Session paper-facts claimed the same decision unseen and
built it first (#896, ADR-048, with the `password-hashing` prompt's citation), so this change keeps that version and
adds nothing to it.

The test fixtures that stood for a correct app sent a policy without the two directives and were brought up to it,
as was the example app `examples/notes-with-users`. **Eight guards broken in turn, each caught:** each of the three
shortfalls not looked for, `default-src 'none'` not standing in, `'none'` among other values counted, capitals not read
through (each by the new probe test), the policy not judged at all (that test and the private-page test, whose fake app
now has a policy without `base-uri`), and the V11.4.2 citation removed (the coverage document's test, before the
citation was taken from #896).

The `security-headers` prompt (shown) asks for neither directive, so an app built with it now gets this finding; its
words are for a prompt trial to change, not this change.
