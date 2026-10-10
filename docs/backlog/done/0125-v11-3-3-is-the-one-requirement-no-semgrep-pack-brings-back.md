# V11.3.3 is the one requirement no semgrep pack brings back, and `sv` could own it outright

**Status:** done, as its markers read on 8 October 2026

Found on 26 September 2026 while reading the coverage maps after #164 made the semgrep count
honest; **claimed on 26 September 2026 by session securevibe-e8**, and session relaxed-nobel-27acfa is pointing at this item from the step 3
write-up rather than duplicating it. Four requirements lost their credit when the count started
following the pack: V4.4.1, V9.2.1, V11.3.3, and V11.4.3, each mapped to semgrep alone with no
other tool behind it. From relaxed-nobel-27acfa's measurements, `p/default` reaches three of them
and **not V11.3.3**. So three are a pack decision and the fourth is not; adding packs leaves it
uncovered forever.

It does not have to be. V11.3.3 asks that "encrypted data is protected against unauthorized
modification, preferably by using an approved authenticated encryption method or by combining an
approved encryption method with an approved MAC algorithm" — a question about a call site, which is
what `data/ast-rules.json` is for. Its neighbours are already there: `ast.weak-cipher` cites V11.3.1
and V11.3.2 across fourteen languages, `ast.weak-hash-function` cites V11.4.1 across fourteen. The
call sites are the same ones — `createCipheriv`, `openssl_encrypt`, `Cipher.getInstance`, `AES.new`
— and what differs is the argument: a non-authenticated mode (`aes-256-cbc`, `aes-256-ctr`,
`MODE_CBC`, `AES/CBC/PKCS5Padding`) where `ast.weak-cipher` looks for a retired cipher or ECB.
`argumentPatterns` and `safeArgumentPatterns` already express exactly that shape, GCM, CCM, OCB,
SIV, ChaCha20-Poly1305, Fernet and libsodium's secretbox being the safe side, so it is a data entry
and not a change in Rust.

**The catch, and it decides the shape.** CBC combined with a separate HMAC satisfies the
requirement, and no single query can see the HMAC: it is a different call, often in a different
function. A rule written the obvious way flags every correct encrypt-then-MAC as a finding. Two
honest ways out, and the difference matters:
- `"confidence": "low"`, the way `ast.file-path-from-value` already handles a question it cannot
  settle from one call site. Cheap, consistent with what is there, but a clean run still credits
  V11.3.3 as checked, which for an app doing CBC plus HMAC is the right answer reached by luck and
  for an app doing raw CBC is the rule having missed nothing.
- Make it finding-only. `findings_against` exists for adapters and **has no equivalent for AST
  rules** — `nothingToFind` is a per-language "this language has no such construct" note, not this —
  so that route is a change in `ast.rs` and the rule schema, not a data entry. It is the more honest
  of the two, and it is the more expensive.
  *(Note from session securevibe-e8, 26 September 2026: AST rules have had `findingsOnly` since the
  V4.4.1 WebSocket rule, `ast.plaintext-websocket-url`. A rule with it is never credited by a clean
  run, and `coverage.py` shows it as finding only, so this route is a data entry after all.)*

Whoever takes it should also break it and count: every (rule, language) pair in this file is
required to have a found and a not-found witness, and the pair that matters here is CBC-with-a-MAC,
which is the case a single query gets wrong.

**Done the same day** as `ast.unauthenticated-encryption`, finding-only at low confidence, in all
fourteen languages; its fix says encrypt-then-MAC code is already correct. See DESIGN, "Encryption
that cannot show it was changed (V11.3.3)".
