# Using OAuth and being the authorization server

`sv` was asking every app with a "Sign in with Google" button how it validates redirect URIs against a
client-specific allowlist, how long its authorization codes live, and whether a user can review and revoke the
consents they have granted. Those are ASVS V10.4, V10.6, and V10.7, and they are written for whoever **runs** the
authorization server. A clinic booking app that sends patients to Google runs none of it.

The whole of V10 was gated on one condition, `oauth`, which conflates two different jobs:

| section | whose requirements they are |
|---|---|
| V10.1 generic, V10.2 OAuth client, V10.3 resource server, V10.5 OIDC client | the app that signs people in through somebody else |
| **V10.4 authorization server, V10.6 OpenID provider, V10.7 consent management** | the app other applications sign people in through |

So there is a second condition, `authorization-server`, and three section-level rules keyed on it. Five of the
misplaced requirements are Level 1, which is why this was worth doing before the Level 2 ones: they were the
first thing a small app was told it had to meet.

### The entailment, and why it is drawn where it is

A condition nobody has answered produces *not assessed*, never *does not apply* — the rule the rest of this
engine is built on. Applied literally here, every manifest written before this question existed would have had
V10.4, V10.6, and V10.7 reported as unanswered, including the great majority of apps with no OAuth anywhere near
them.

One fact rescues that without guessing: **running an authorization server is a way of using OAuth**, so an app
that uses none is certainly not one. That is an entailment, not an inference about what an app probably does,
which is why it is safe to draw where this engine deliberately draws nothing. It lives in `Manifest::claims`,
beside the same move for the AI sub-claims, and the order of its arms is the part that matters:

```rust
let authorization_server = match (c.oauth, c.authorization_server) {
    (_, Some(true)) => Some(true),      // an explicit yes, first and never overruled
    (Some(false), _) => Some(false),    // no OAuth at all means no authorization server
    (_, stated) => stated,              // otherwise whatever the manifest says, silence included
};
```

A manifest saying both "no OAuth" and "runs an authorization server" contradicts itself, and only one reading of
it is safe to act on: the one that keeps the requirements. Putting the `Some(false)` arm first — which is what
the AI sub-claims do — deletes V10.4 from somebody who has just said in the same file that they run one. Two
tests hold that arm in place, one on the claim and one on the requirements a reader of the report would actually
miss.

The entailment is drawn in `claims()` rather than after `resolve()` for a second reason: drawn afterwards, the
context would act on an answer while the resolved claim beside it still said *nothing answered this*, and the
report would print an exclusion next to the statement that nobody had decided it.

### Authlib, and the corroborator that nearly undid the whole thing

`authorization-server` has a corroborator, so an app that really ships one gets these requirements back whatever
`securevibe.toml` says. Writing it turned up the trap: **Authlib is both a client library and a server library**.
It was in the first draft's package list, and a Flask app doing "Sign in with Google" — which installs Authlib
exactly that way — would have been read as running an authorization server, undoing the fix for one of the most
common shapes of app there is. The same holds for `zitadel/oidc` in Go.

Dual-purpose libraries are therefore deliberately absent from the package lists. Only their server-side class
names count, in `source`: `AuthorizationServer(` for Authlib, `op.NewOpenIDProvider` for zitadel. C# has no
packages listed at all, because `sv` does not read a `.csproj`; Duende IdentityServer and OpenIddict are found
by the line that registers them.

Putting `authlib` back as a package passed the entire suite. Three witness files, an OAuth-client negative test
and the "every corroborator has a witness" guard all stayed green, because every one of them writes a source
file and none wrote a dependency list. The gap was on the side that mattered, and it now has a test of its own —
one that asserts the `requirements.txt` really was read as OAuth before asserting what was not found in it,
because a fixture the scanner skipped would have passed the real assertion for the wrong reason.

### What it does to v1

`data/knowledge/applicability.json` is shared, so this is decided for both products. v1 generates apps with
local accounts and hard-codes `oauth: false`; it now hard-codes `authorization-server: false` beside it. Every
requirement in V10.4, V10.6, and V10.7 was excluded for a v1 app before this change and is excluded after it —
**no requirement moves buckets**. What changes is the sentence the owner reads: "this app uses its own local
accounts" gives way to "this app does not run an OAuth authorization server", which is the true reason, and the
one that stays true if v1 ever grows OAuth sign-in. v1's own test for that reason was updated to say so.
