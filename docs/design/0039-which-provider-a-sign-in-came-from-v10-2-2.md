# Which provider a sign-in came from (V10.2.2)

A mix-up attack works on an app that signs in through more than one provider: a sign-in started
with one is answered by another, and an app that does not check which provider answered hands the
code or the token to the wrong one. V10.2.2 asks for the defense: check the `iss` the provider's
return names (RFC 9207) and the `iss` claim in the ID token. The backlog had it waiting on a second
provider. It does not need one: the single test provider can name another in either place.

Two more modes in the test provider: `wrong-iss` puts `http://sv-other-idp.invalid` in the return's
`iss` parameter, and is used up at `/authorize`, since an app that refuses the return never asks for
a token; `wrong-token-iss` puts it in the ID token. The provider's discovery document now also says
`authorization_response_iss_parameter_supported: true`, which is what makes a standard client library
check the parameter.

**Credit only.** Refusing both, with an ordinary sign-in working afterwards, is credited. Taking
either is *not* a finding: with one provider, only that provider can sign the app's tokens, so there
is nothing to mix up, and securevibe.toml does not say how many providers the app uses. The report
says which of the two the app took and why that is not called a failure. Level 2 goes from 62 to 63
of 183.

`examples/oidc-notes` now checks the return's `iss`, and its `flaws.json` can switch off either
check (`iss`, `iss-param`). Run in Docker: the correct app is credited for V10.2.2 beside its four
other sign-in checks; each copy with one check off is not assessed for V10.2.2, naming which, and
loses nothing else. Each guard was removed in turn and every one was caught, the credit on a single
refusal only after a test with the second trick made impossible.
