# A sign-up that tells which accounts exist (8 October 2026)


From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.5; BACKLOG, item 13, the sign-up half of its part (c)). The reset
request and the sign-in were already asked whether they tell an address with an account from one without (V6.3.8);
sign-up was not, though ASVS names it alongside them.

`probe.signup-reveals-account`, in `crates/sv-check/src/signed_in/passwords.rs`, makes an account of its own through
sign-up, then signs up twice more with that address and once with an address nobody has, all with the same password,
and compares the three answers through `reveals_account_check`, as the sign-in and reset checks do: the pair shows
what varies between identical sign-ups, and only a status, words, or a redirect that differ beyond that count. A
difference is a medium finding citing V6.3.8; none is never credit. It runs only where `securevibe.toml` sets a
sign-up, right after the password checks. A limit refusing a sign-up (429), or no answer, leaves the answers
uncompared, and a crash is set aside through `RAISED_ON_A_REFUSAL`.

It never uses A's or B's address. The fake app gives an account the new password when somebody signs up again with its
address, and a real app may too; used with A's address, the check changed the password the later checks sign A in
with, and eleven tests went red. That fault is worth a check of its own, and is on the backlog ("A second sign-up with
a taken address may replace that account's password").

The fake app gained two switches: `signup_reveals_by_status` (409 for a taken address) and `signup_reveals_by_words`
(a different redirect).

Tests: four in `passwords.rs`. The clean app is compared (the step shows three 303s) and neither reported nor credited;
both switches are found, and only by this rule; with no sign-up set, the check does not run; and one sign-up alone
refused as too many is not read as accounts told apart. Six guards broken in turn, each caught: the check never
called, a 429 not set aside, a crash not set aside, the account not made first, the address with no account replaced
by the taken one, and A's own address used.
