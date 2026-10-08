# A reset code handed back in the reset request's own answer (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.5; BACKLOG, item 13, its part (d)). An AI-written reset sometimes
answers the request with the code it just emailed, in a JSON field, a debugging comment, or a redirect: then anybody who
knows an email address can reset that account, without the email. The reset check already followed the email through;
it never looked at what the request itself answered.

`probe.reset-code-in-answer`, in `crates/sv-check/src/signed_in/reset.rs`, runs once the check has found the code in
the email: it looks for each code the emails carried in the answers to the two reset requests for the account, in the
body as far as the run keeps it and in every header (a `Location` carrying the link, say). Only a code standing on its
own counts, not one inside a longer run of letters and digits, and a code shorter than six characters is not looked
for, since it could be in a page by chance (such a code is already reported as guessable). A match is a critical
finding citing V6.4.3, saying where the code was and never the code. No match is never credit: the run keeps only the
start of each answer.

The fake app the signed-in tests use gained a switch, `reset_code_in_answer`, that writes the code into a comment in
the answer to an address's first reset request only. One request is all an attacker needs, so the first answer is the
one that must be read; the switch's single first answer is what shows the check reads it.

Tests: four in `reset.rs`. The clean run says it looked and found nothing; the switch is found whether the account was
seeded or made by sign-up, and only the new rule fires (the two answers for the account differ between themselves, so
the account-revealing check sets that aside); the finding and the steps never hold the code; and a unit test shows a
code found alone in a body or a header, not inside a longer word, not when shorter than six characters, and not in a
crashed request. Six guards broken in turn, each caught: the check never called, headers not read, a code inside a
longer word counted, short codes looked for, the first answer not read, and no match credited. The last-but-one was not
caught at first, while the fake app wrote the code into every answer; it is caught since the switch writes it only
into the first.
