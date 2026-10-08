# A second sign-up that takes a taken account (8 October 2026)



From the backlog item "A second sign-up with a taken address may replace that account's password", found while
building the sign-up half of 13(c) (`0301-a-sign-up-that-tells-which-accounts-exist-8-october-2026.md`): the fake app
the signed-in tests use gave an account the new password when somebody signed up again with its address, and no check
asked whether a real app does the same. One that does lets anybody who knows an address take the account.

`probe.signup-replaces-account`, in `crates/sv-check/src/signed_in/passwords.rs`, makes an account of its own through
sign-up (`resignup.<A's address>`), and signs it in to show it works; an account that does not sign in is not signed
up again, and the step says so. Then it signs up again with that address and another password, and tries both
passwords. The new password signing in is a critical finding citing V6.2.3, since a sign-up that changes a password is
a password change that asked for neither the current password nor anything else; the description says whether the old
password still works beside it. The new password refused is never credit: it says nothing about the app's own
password change, so the rule is listed as only ever a finding. It runs only where `securevibe.toml` sets a sign-up,
right after the check on sign-ups telling accounts apart, and never uses A's or B's address, whose passwords the
later checks need.

The fake app's sign-up now keeps accounts apart by default (an address that has an account is sent to the sign-in
page and left as it was), and gives the account the new password only behind a switch of its own,
`signup_replaces_account`.

Tests: four, in `crates/sv-check/src/signed_in/resignup_tests.rs` (a file of their own, per the working rule of the
same day). The clean app is tried (the step shows the new password refused and the old one still signing in) and
neither reported nor credited; the switch is found, by this rule only, with every other check's findings and credits
the same as on the clean app; an account that never signs in is not signed up again; and with no sign-up set, nothing
is tried. Seven guards broken in turn, each caught: the check never called (2 tests), the new password not tried (1),
the account not shown working first (2), A's address used in this check (8), A's address used in the check on telling
accounts apart (3), the old password still working taken as the finding (21), and a refused takeover credited (2).
