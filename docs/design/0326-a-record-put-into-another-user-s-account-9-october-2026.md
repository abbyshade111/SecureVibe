# A record put into another user's account (9 October 2026)

Part (a) of finding 13 of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7 October 2026"),
on `owned.create`: the running app's check asked about fields the request should not set (mass assignment) only at
sign-up, where it adds a role. The commoner place is a record's owner. An app that takes `user_id` from the request
that creates a note lets anybody signed in put a note, a message, or an order into somebody else's account.

**The check.** `probe.owner-field-trusted`, only ever a finding, at high severity, citing V15.3.3 (mass assignment),
V8.2.3 (a field no user may write), and V8.2.2 (one user's data reaching another's). It runs with the other checks on
the `owned` record, once the first user (A) has read back their own record and the second (B) has signed in:

1. The record A read back is looked at for the field naming its owner: `user_id`, `owner_id`, `userId`, `ownerId`,
   `author_id`, `created_by`, or `owner`, written as JSON with a string or a number, in a JSON answer or in JSON on a
   page. The first found gives the field and A's value.
2. B creates two records: one as stackvet.toml says, and one with that field added to the body, set to A's value. A
   JSON body keeps the value's type, so an app that checks it is a number still takes it. A form gets it as text.
3. A opens each record's own address and every page where A's records are listed. B's record with the field shown to A,
   while B's plain one is not, is the finding.

**What it does not claim.** A request with the field refused, or accepted and kept as B's, credits nothing: seven
guessed names say nothing about an eighth. When A's record names no owner by one of them, there is no value to send,
and the report says V15.3.3 was not assessed and why. When A is shown B's plain record as well (an app that shows
everybody's records, which the reading check reports), being shown the other proves nothing, and the report says so.
A `create` with neither `form` nor `json` has no body to add a field to, and the report says that too.

**Left for later.** The rest of part (a): `creates` (the other kinds of records an app makes) and `change-email`,
sending `role` and an owner field where they are not expected.

**How it is held.** `crates/sv-check/src/signed_in/owner_field_tests.rs`, against the scripted app with two new
switches: a note's page naming its owner, and an owner taken from the request. Found when both are on, not when the
owner is set on the server (both records accepted, so the field did reach an app that ignored it), not assessed when
the record names no owner, and not assessed when A reads any record. Two guards broken in turn, each caught by the test
written for it: the control removed (the app that shows everybody's records reported), and the field never added (the
flaw missed).
