# Changing the email address without the password (3 October 2026)

V7.5.1 asks for the password again before anything that could take over an account is changed, and the email address
is the first of those: whoever controls it can reset the password. The manifest takes a new entry, `change-email`,
with `{password}` where the app asks for the password and `{new_email}` for the new address.
`probe.email-change-without-password` follows `probe.password-change-without-current`:

- **It is only ever done to an account made for it through `signup`.** A and B have to keep signing in by their
  addresses for every later question, so without `signup` it is not assessed.
- **The wrong password first.** If the new address then signs in with the account's password, the change took, and
  that is the finding (high).
- **Then the right password, as the control.** That change has to take, its new address signing in, before the
  refusal means anything. Then the check is credited for V7.5.1. A change that never takes leaves it not assessed.
- **A change counts as taken only when the new address signs in.** The proposal also allowed a private page showing
  the new address. That was left out: a page saying "we sent a link to confirm your new address" shows the address
  too, and the change has not happened. So an app that signs in by user name, or that waits for the new address to be
  confirmed, leaves V7.5.1 not assessed rather than passed, and the reason says so.
- **It credits one attribute.** V7.5.1 also names the phone number, MFA settings, and the other ways back into an
  account. The credit names the one change it tried; the report never says V7.5.1 passed.

The scripted app gained `POST /account/email`, with two flaws: the password not checked, and a change that answers as
though it worked and changes nothing. The first is in the "signed up" scenario of
`a_crash_never_turns_a_finding_into_a_pass`, and the requests the credit rests on are listed in `RESTS_ON_A_REFUSAL`.
The example app has no email change yet, so this has not been run against a real app.
