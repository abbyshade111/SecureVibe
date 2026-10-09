# A role sent with an email change (9 October 2026)

The `change-email` part of finding 13(a) of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7
October 2026"). The running app's check sent role fields only at sign-up. An app that refuses them there can still take
them from a request that changes the account later, and an email change is the commonest one an ordinary account sends.

**The check.** `probe.email-change-role-trusted` is only ever a finding, at critical severity, citing what the sign-up
check cites: V8.3.1 (an authorization decision resting on what the client sent), V15.3.3 (mass assignment), and V8.2.3
(a user writing a field they have no permission to). It runs beside the sign-up check, when stackvet.toml has `signup`,
`change-email`, and an `admin` page:

1. An account is made for it through sign-up, never A or B, whom the other checks rely on. It is shown signed in.
2. It asks for each admin page. Only those refused to it go on. A page it opens already is the admin-page check's
   finding, not this one's.
3. It sends the email change with the right password and the sign-up check's five role fields added (`role=admin`,
   `is_admin=true`, and the rest).
4. It asks for those admin pages again: with the session it had, and signed in afresh under its old and its new
   address, since an app may read a role into a session only at sign-in. An admin page that opens is the finding.

**What it does not claim.** Refused again, the account's run is recorded as asked with no requirement credited: five
guessed names refused say nothing about a sixth. Without `change-email`, the report says so. Without `signup` or an
admin page, the sign-up check has already said these requirements were not asked, and this check adds nothing.

**Its own rule.** The claim put this under `probe.role-field-trusted`. It has a rule of its own instead, because the
check that a crash never turns a finding into a pass (ADR-021) follows a rule by its name. Under one name, the sign-up's
finding, withheld when one of its requests crashed, read as turned into a pass by this check's clean record. The admin
pages asked after the change, and the change itself, are the requests this rule's record rests on, so a crash in any of
them withholds it.

**Left for later.** `creates`: stackvet.toml gives no way to read back what those requests make, so an owner field sent
there could not be seen to take.

**How it is held.** `crates/sv-check/src/signed_in/email_role_tests.rs`, against the scripted app with a new switch,
an email change that makes an admin of an account asking for it: found with the switch, and not by the sign-up check;
recorded as asked and crediting nothing without it, with the step showing the account refused first and the change
taken; and said to be unasked without `change-email`, with nothing added without `signup`. The switch is in the crash
sweep's sign-up scenario. Three guards broken in turn, each caught:
- No role fields sent: the finding's own test failed.
- No refusal asked first: the test of an admin page open to everybody failed.
- The rule left out of what rests on a refusal: the crash sweep failed.
