# A failed sign-in that tells which accounts exist (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.5; BACKLOG, item 13, the sign-in half of its part (c)). A sign-in
that answers "no account has that email" for one address and "wrong password" for another tells anybody which
addresses have accounts (V6.3.8). The reset check already asked this of the reset request; nothing asked it of
sign-in.

`probe.signin-reveals-account`, in `crates/sv-check/src/signed_in/signin.rs`, makes two sign-ins with a wrong password
for an account that exists (one made for it through sign-up, or B's) and one for an address with none, each in a fresh
session with the page's anti-forgery token. The answers are compared by the reset check's `reveals_account_check`, now
given the rule and its wording (`AskedAbout`): the real account's pair shows what varies between identical attempts,
and only a status, or words, or a redirect that differ beyond that count. A difference is a medium finding citing
V6.3.8; none is never credit, since answers alike can still differ in how long they take.

Where it runs was found by the tests, not chosen. Anywhere before the guessing check, its three wrong passwords used up
part of a limit that counts by address, and five of the guessing check's tests went red; the run is budgeted to stay
under such a limit until then. So it runs last, after the guessing check, and is the one exception
`a_run_signs_in_no_more_often_than_the_spec_says` allows to follow the guesses. A limit still refusing there (429), or
no answer, leaves the three answers uncompared, and the step says so; a crashed attempt is set aside through
`RAISED_ON_A_REFUSAL`, after `a_crash_on_a_correct_app_raises_no_finding` showed a crash on the "no account" attempt
read as a different answer.

The fake app gained two switches, `signin_reveals_by_status` (404 for an address with no account) and
`signin_reveals_by_words` (different words for each).

Tests: five in `signin.rs` and one in `passwords.rs`. The clean app is compared (the step shows three 403s) and not
reported or credited; both switches are found, whether the account was seeded or made by sign-up, and only by this
rule; a limit the guessing check left refusing leaves the answers uncompared; one attempt alone refused as too many is
not read as accounts told apart; and a unit test shows a status judged only when the pair agrees. Six guards broken in
turn, each caught: the check never called, a 429 not set aside, a crash not set aside, the pair's statuses not
compared, the words not compared, and the same account used for all three. The pair's statuses were caught only after
the unit test was added, since no scenario made the pair disagree.
