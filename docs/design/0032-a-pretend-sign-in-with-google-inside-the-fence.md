# A pretend "Sign in with Google" inside the fence

An app whose people sign in through Google, Microsoft, or any other OpenID Connect provider carries
requirements about how it treats what comes back: that a sign-in is finished only in the browser
that started it (V10.1.2, V10.2.1), that the ID token's `nonce` is the one the app sent (V10.5.1),
that the token was issued to this app and not another (V10.5.4), and that its signature is checked
against the provider's published keys (V6.8.2). None of those can be asked of Google itself, which
never misbehaves on request and is outside the fence anyway. Level 2 goes from 58 to 63 of 183.

A `[stack.run.oidc]` section names the address that starts a sign-in and a page only a signed-in
person sees. `sv run` then starts a test provider on the fenced network and gives the app
`OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` (the secret made fresh for each run). An
app that reads those three settings, as it would read its real provider's, signs in through the
test provider without knowing it is one. `examples/oidc-notes` is such an app, in Node with nothing
but its standard library, with a `flaws.json` that switches each of its checks off.

### The provider is `sv`'s own

A short script (`crates/sv-run/assets/oidc-provider.mjs`) in the stock `node:22-alpine` image,
hardened like the mail server and the sidecar. It serves discovery, its keys, an authorization
endpoint that approves at once, and a token endpoint that checks the client's secret, the code's
single use, the `redirect_uri`, and PKCE. No ready-made test provider was used because the point is
to misbehave on purpose: before one sign-in, the probe asks it for a token with a wrong `nonce`, a
wrong `aud`, no signature (`alg: none`), or a signature from a key it never published, and it goes
back to normal after that one token.

### Controls before credit, as with the test accounts

The private page has to be shut before anybody signs in, and an ordinary sign-in has to open it, or
nothing is said. After the five refusals, an ordinary sign-in has to work again, or none of them is
credited: an app that stops signing anybody in after the first bad token refuses everything, and
that is not a check of the token. V6.8.2 needs both bad signatures refused for credit, and either
one accepted for a finding; one refused and the other not tried says nothing. An app that sends no
`nonce` is not judged on V10.5.1, and the report says PKCE or `state` may be protecting it instead.

The crossed sign-in starts two sign-ins in two sessions and delivers the first one's return to the
second. The app is credited if it refuses, whatever refuses it: `state`, PKCE, and a `nonce` kept in
the session each stop it, and an app that checks only one of them is protected. So an app with its
`state` check switched off, but PKCE and the nonce kept, is rightly credited.

### A fault in every run, found by this one

The first run against the example app said the sign-in address gave no answer. It did answer, when
asked from a terminal. The sidecar sends each request as `echo … | nc`, and BusyBox `nc` closes its
sending half when the input ends. Node reads that as the browser having gone away and drops the
reply to any route that answers after a moment (here, one waiting on the provider). Every earlier
app answered at once, so the fault was invisible until now. The request is now written by a
command that keeps the connection open until the answer arrives (`nc -e`, under a `timeout`), and
`an_answer_a_node_server_takes_a_moment_over_still_arrives` fails if that is ever undone.

### What the guards caught

Each guard in `oidc.rs` was removed in turn and the tests run. Two survived the first time: V6.8.2
was credited when one bad signature was refused and the other could not be tried, and a provider
was asked for a wrong-`nonce` token by an app that never sent one. Each now has a test that fails
without it.

Left for later: V6.8.1 and V10.2.2 need two providers, V10.5.3 needs metadata that an app reads at
start-up to change, and V10.5.2 and V6.8.4 depend on what the app decides rather than on what the
provider sends.
