# A session that is one fixed key (8 October 2026)


ASVS V7.2.2 asks that sessions rest on tokens made at each sign-in, not on static secrets or keys (ADR-067).
`probe.session-id-weak` (V7.2.3) already signed the first test user in a second time near the end of the signed-in
checks, and found a cookie repeated between the two; it skipped an app that signs in with a token. That second
sign-in now also feeds `probe.session-token-static`, and is made for token apps too: each cookie the sign-in answer
set, and the token when there is one, are compared between the two sign-ins.

The same value twice is the finding (high): a fixed key for everybody, or one per person, is the same at every
sign-in. Every value different is credited, once a private page has opened with the new session, so a sign-in that
quietly failed and handed back an empty session is not taken for a new one; how the values are made stays V7.2.3's
question. A second sign-in answered by the app's limiter, one that set again only some of the values the first set,
and one whose new session did not open the private page are each said and neither found nor credited. A repeated
cookie breaks both requirements, so it is found by both rules, and the tests that hold each flaw to one rule say so
for this one.

The proposal compared the second test user's sign-in too. It is not: `sv` promises at most 60 sign-ins in a run
(`SIGN_INS_IN_A_RUN`), the busiest run in the tests was already at that number, and the second user is signed in only
by the owned-records check, when there is one. A key fixed for everybody already shows as the same value at two sign-ins
of one person.

Checked: the signed-in tests, with a fake app that gives a fixed cookie or a fixed token, a new one each time,
a later sign-in that fails quietly, sets no cookie, or is refused by a limiter, and no private page. Seven guards
broken one at a time, each caught, one of them only once the limiter case was added. Not run end to end against an
app under `sv run`, which needs Docker.
