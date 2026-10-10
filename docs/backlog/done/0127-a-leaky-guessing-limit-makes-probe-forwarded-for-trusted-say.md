# A leaky guessing limit makes `probe.forwarded-for-trusted` say the opposite of the truth, in both directions

**Status:** done, 10 October 2026

Found on 26 September 2026 reviewing #130/#131. **Claimed on 26 September 2026
by session securevibe-e9, and done the same day** with the fix below: two claimed attempts from two
addresses, then two plain ones. `forwarded_check`
in `crates/sv-check/src/signed_in.rs` sends one wrong attempt claiming `203.0.113.77` and one
claiming nothing, and calls it a finding when the first is answered as the first attempt was and
the second is still refused. That pattern is produced by any limiter that lets one attempt through
per interval — a token bucket, a sliding window, `nginx limit_req`, `express-rate-limit` — whatever
it thinks about addresses.

Reproduced with a fake app whose limit releases one attempt each time it refuses one
(`lockout_leaks`), a limit counting by address, `locks_out_after: Some(6)`, `policy(Some(6))`:

| limiter | reads X-Forwarded-For | finding |
|---|---|---|
| steady | no | none — correct |
| steady | **yes** | **found** — correct |
| leaky | no | **found — a false positive on a correct app** |
| leaky | **yes** | none — **a false negative on the real flaw** |

The two errors swap places: the leak invents the finding on the app that ignores the header, and
hides it on the app that trusts it, because the same leak lifts the plain control too. And the
evidence line for the false positive is **character-for-character the one for the true positive** —
*"answered 403, as the first attempt was; one more claiming nothing: still refused (429)"* — so
nobody reading the report can tell them apart. The finding's own words then assert the wrong
conclusion: *"Nothing sits in front of the app here, so the address came from the request itself."*

**A tested fix.** Two spoofed attempts in a row, each from its own address (`.77`, `.78`), then two
plain ones; credit the finding only when both spoofed attempts were answered as the first was and
both plain ones were refused. A one-per-interval leak releases one of the two, so the pattern
breaks. Measured against the same four rows: the false positive goes, the three correct outcomes
stay, and the full suite still passes (367 tests). The false negative stays — a leaky limiter still
hides a genuinely header-trusting app — which is the safe direction and probably needs timing to
do better; the check is finding-only, so nothing is credited either way.

Note also that alternating the attempts (plain, spoofed, plain, spoofed) does **not** work, and it
is the first thing that comes to mind: a limiter releasing one attempt in two produces exactly that
alternation.

**Checked against origin/main, 10 October 2026:** built: `crates/sv-check/src/signed_in/signin.rs` `forwarded_check`, which needs both spoofed answers refused, and both plain ones.
