# A sign-in token caught naming where its key is (5 October 2026)

The second half of V9.1.3's work (BACKLOG, "V9.1.3", item 1), beside the code-reading rule above: the running app is
asked, and seen. When the app's own sign-in token is a JWT and the token checks have a private page the token alone
opens, the token is sent to that page twice more. Each copy is the real one with its header changed to name an
address on the test model's server, `/_sv/keys/<tag>`, once as `jku` (where a set of keys is) and once as `x5u` (where
a certificate is), each with a tag made for that request. The signature is left as it was, so neither copy is a token
the app should accept; an app that follows the header goes for the key before it can know that. The test server
records each request by its tag, and is then asked whether the app came for either.

- **Fetched is the finding** (`probe.app-token-key-source-followed`, V9.1.3, high, CWE-347 and CWE-918): the token
  chose where the key that checks it comes from, and the app went to an address on its own network that nobody
  listed. Fetching shows the fault without the app having to accept anything, so `sv` never needs a key the app
  would take. High rather than critical: the fetch is seen, but whether the app would then trust a key from there is
  not.
- **Not fetched is never credit,** and says why: an app that ignores the header, as the common token libraries are
  thought to unless the app's own code follows it, cannot be told from one that checks it against a list. The same
  reasoning as `probe.fetch-goes-anywhere`.
- **A test server that could not be started, or could not then be asked,** is said, and finds nothing. With no test
  server nothing is sent.

The test server answers `/_sv/keys/<tag>` with a set of public keys made when it starts (an EC key, `kid`
`sv-test-key`), so an app that follows the token gets an ordinary answer; nobody holds the private part, and the
answer never carries it. `/_sv/fetched/<tag>` answers for it as for the fetch check's addresses.

Since `sv` learns whether the app's tokens are JWTs only after signing in, **any run that signs in now starts the test
model**: one more small container. The signed-in checks reach its address through a new `Http::model_address`, which
`Patient` passes on; a wrapper that did not would read as having no test server, so a test breaks that.

Not covered: `jwk` (a key written into the token itself), which needs no fetch and so cannot be seen this way; a run
would have to sign a token with a key of its own, and `sv` has no signing code. The code-reading rule speaks to it.
`kid` stays out by the owner's word on item 4 of the token checks. The proposal in `docs/PARTIAL-CHECKS.md` to try a
wrong key through the test sign-in provider, for apps that sign in through another service, is not built.

Tested against the scripted app (a `jwt_key_source_followed` flaw, and a test model it can be told is up), carried as a
bearer and as a cookie: found, not fetched, no test server, a server that cannot be asked, and each request's own
address. The real test server is run with Node and asked for `/_sv/keys/` (recorded, public keys only). The crash
sweep's token scenario carries the flaw. Eleven guards broken in turn, each caught by between one and five tests. Not
shown in a real run: no container backend was available, so starting the test model for a signed-in run, in
`sv-run`, is read in the code and not seen working.
