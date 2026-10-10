# A second sign-up with a taken address may replace that account's password

**Status:** done, 8 October 2026

Found on 8 October 2026 by session
securevibe-e9 while building 13(c) through sign-up: the fake app the signed-in tests use answers a sign-up for an
address that already has an account by giving that account the new password, and no check asks whether a real app
does the same. An app that does lets anybody who knows an address take the account by signing up with it. To build:
make an account through sign-up, sign up again with its address and another password, and see which password then
signs in; the new one signing in is the finding, the old one still working and the new one refused is evidence the
app keeps accounts apart. Which requirement it cites needs reading first. **Not claimed.**
**Claimed 8 October 2026 by session securevibe-e9**, at the owner's word ("please go ahead with that item"), in
branch `claude/securevibe-e9-resignup`. It cites V6.2.3 ("password change functionality requires the user's current
and new password"): a sign-up that replaces an account's password is a password change that asked for neither. No
requirement names sign-up itself, and V6.3.8 is about telling accounts apart, not taking them. Only ever a finding:
the old password still working shows nothing about the app's own password change. The fake app's sign-up will keep
accounts apart by default, with the replacing behavior behind a switch of its own.
**Done 8 October 2026** (session securevibe-e9): `probe.signup-replaces-account`, a critical finding citing V6.2.3
when signing up again with a taken address gives that account the new password; the fake app keeps accounts apart by
default. Design entry `docs/design/0304-a-second-sign-up-that-takes-a-taken-account-8-october-2026.md`.
