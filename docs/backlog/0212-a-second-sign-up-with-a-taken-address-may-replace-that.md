# A second sign-up with a taken address may replace that account's password

**Status:** open

Found on 8 October 2026 by session
securevibe-e9 while building 13(c) through sign-up: the fake app the signed-in tests use answers a sign-up for an
address that already has an account by giving that account the new password, and no check asks whether a real app
does the same. An app that does lets anybody who knows an address take the account by signing up with it. To build:
make an account through sign-up, sign up again with its address and another password, and see which password then
signs in; the new one signing in is the finding, the old one still working and the new one refused is evidence the
app keeps accounts apart. Which requirement it cites needs reading first. **Not claimed.**
