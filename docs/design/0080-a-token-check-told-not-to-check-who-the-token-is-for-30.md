# A token check told not to check who the token is for (30 September 2026)

V9.2.3 asks that a service accepting a token checks the token's audience, the `aud` field saying which service the
token was made for. Without that check, a token a sign-in server made for one service is accepted by every other
service that trusts the same server. Most token libraries check the audience only when the code names one, and a few
also have a setting that switches the check off; tutorials copy the setting to make an error go away.

`ast.token-audience-not-checked` reports those settings: `verify_aud` set to false in PyJWT and python-jose (a
dictionary key or `dict(verify_aud=False)`) and in ruby-jwt; `ValidateAudience = false` in .NET's
`TokenValidationParameters`, in an initializer or an assignment; `validate_aud = false` in Rust's `jsonwebtoken`, set
on the field or in the struct; and, in Go, `SkipClientIDCheck: true` in `go-oidc` and `WithoutClaimsValidation()` in
`golang-jwt`, which skips the audience along with every other claim. Each was read from the library's own source or
documentation this day (PyJWT 2.15.1, python-jose 3.5.0, ruby-jwt 3.3.0, `jsonwebtoken` 9.3.1 for Rust, go-oidc
3.11.0, golang-jwt 5.2.1, and Microsoft.IdentityModel.Tokens 8.1.2). The last says an `AudienceValidator` the app
sets still runs when `ValidateAudience` is false, and the finding's advice says so.

It is only ever a finding. What it cannot see is the more common fault, a check never given an audience at all:
that is only a fault for tokens another service signed, and telling those from the app's own tokens needs more than
one file. JavaScript's `jsonwebtoken`, `jose`, `express-jwt`, and `passport-jwt` have no switch at all (read from
each one's documentation or source this day), nor has any library known for Java, Kotlin, PHP, Dart, Swift, C, or
C++, so those languages have nothing to find, and each says why.

The test table has a case each way for the five languages with a switch, and the same setting left on, a different
check switched off (`verify_exp`, `ValidateLifetime`, `validate_exp`), and a key that only begins with `verify_aud`.
Broken on purpose ten ways, each caught: any key, name, or field counted in each language, any value counted in C#
and Rust, any keyed value counted in Go, and `True` counted as well as `False` in Python and Ruby.

**Not done here.** Whether `probe.oidc-audience-not-checked`, which already tests the app as a client of a test
sign-in server with a token for another audience, also speaks to V9.2.3 is the owner's call (BACKLOG, partial checks
item 2). Keycloak's `verify-token-audience` in a JSON settings file is not read, since the rule reads code.
