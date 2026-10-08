# Two people with one email address at the sign-in provider (29 September 2026)

V10.5.2 asks that an app signing people in through another service ("Sign in with Google") tells who someone is by
the provider's `sub` claim, which the provider never gives to anyone else, and not by their email address, which can
pass from one person to another: a reused work address, or a provider that lets people choose theirs. An app that
looks people up by email address signs whoever holds the address next in to the first person's account.

The test provider could already get a token wrong in six ways. It gains two identities that are each correct:
`other-person`, a different `sub` with the same email address, and `new-email`, the same `sub` with a different one.
Its account-details answer (`userinfo`) now carries the same identity as the ID token it went with.

Telling whose account a sign-in reached needs something only that account has. So `[stack.run.oidc]` gains two
optional entries: `create`, a request that saves something as the signed-in person with `{marker}` in a field (and
`{csrf}` where the page's anti-forgery token goes), and `shows`, a page where it appears (the private page when not
given). The probes sign in, save a mark, and sign in again in a new session: the mark showing then is the control,
and without it nothing is said. Then:

- A different person with the same email address sees the mark: a finding (High), naming deliberate linking by
  email as the one reason an app might do it on purpose.
- The same person, after their email address changed, does not see it: a finding (Medium), since the app took them
  for somebody else and so tells people apart by email address.
- The first kept apart and the second still in their account: credited, `probe.oidc-user-keyed-on-email`.
- A sign-in refused, or anything else: not assessed, saying which. Refusing a second person with the same address
  is safe, but does not show which account they would have reached.

Without `create`, the report says how to add it. It is asked only when an ordinary sign-in still worked after the
broken tokens, as the other sign-in credits are.

Broken on purpose seven ways, each caught: the control dropped, the different person's verdict inverted, the
changed-address finding dropped, credit given on one half alone (which nothing caught until a fake app keyed on
`sub` and email address together was added), a refused sign-in read as not seeing the mark, the question asked after
ordinary sign-ins stopped working, and the mark not filled into `create`. The provider script was run on its own
with Node, and each mode's ID token and account-details answer read back.

The example app `examples/oidc-notes` gains a notes page for `create` and `shows`, keyed on `sub`, and a flaw
`"email"` in its `flaws.json` that keys accounts on the email address instead. The real provider and that app were
run together under Node, outside any container, and walked through the same steps by a small script (not `sv`
itself): as written, the mark showed on signing in again, a different person did not see it, and the same person with
a new address did; with `"email"`, the different person saw it and the same person with a new address did not.

**Not done here.** The static companion the backlog entry names, a user lookup keyed on the email claim in the
sign-in callback. The provider sends both identities with `email_verified: true`; an app that links by email only
when the address is verified is still found, which is the point, since verified at the provider is not the same as
belonging to the same person.
