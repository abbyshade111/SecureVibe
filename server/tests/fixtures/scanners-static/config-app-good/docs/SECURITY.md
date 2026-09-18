# Security policy

Contact: security@example.com

## Signing in

Sign-in is by email address and password only; there is no other way in. After five wrong attempts in fifteen
minutes the account is locked out temporarily and the attempt is logged. Passwords must be at least twelve
characters, are checked against a list of common passwords, and the words that cannot be used as passwords include
this app's own name and the business name.

## Administrators

An administrator must also complete a second step at every sign-in: a one-time code from an authenticator app.
Losing the phone is handled with recovery codes, which are shown once and stored hashed.
