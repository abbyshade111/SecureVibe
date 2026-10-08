# Three small signed-in checks: a header that names a user, and what a password change does (29 September 2026)

Three requirements the signed-in checks were already close to, each added where the requests it needs are already
being sent.

**V4.1.3, a header that names a user.** Some apps sit behind a proxy that signs people in and then tells the app who
they are in a header such as `X-Remote-User`. If the app believes that header when no proxy is in front of it,
anybody can type it. After the suite has shown that signing in opens the private pages and that a stranger is
refused, it asks each refused page again, not signed in, carrying one of eight such headers at a time
(`X-User-ID`, `X-User`, `X-Forwarded-User`, `X-Remote-User`, `Remote-User`, `X-Auth-Request-User`,
`X-Auth-Request-Email`, and `X-Forwarded-Email`), naming the first test user (or, for `X-User-ID`, the number 1). A
page that opens is a finding, `probe.identity-header-trusted`, naming the page and the header. It is never credited:
eight names are not every header a proxy may use, so a clean answer to them does not show the app believes none. A
page already open to strangers is left out, since opening it proves nothing about a header; that is the private-page
finding's to report.

**V7.4.3, other sessions after a password change.** Just before the change that should take, the check signs in a
second session of the same account, then the session that makes the change, then shows that the second session still
opens a private page. That last step is a control: an app that allows one session per account ends the second one at
the second sign-in, and without the control its being shut after the change would be credited to the change. After
the change, the second session asks again. Shut is credited, `probe.password-change-ends-sessions`. Still open is not
a finding: V7.4.3 is also met by an app that offers to end the other sessions, and an offer on a page cannot be seen
from here, so it is not assessed and the owner is asked to check. A control that fails is not assessed too.

**V6.3.7, an email after a password change.** The check counts the account's emails in the mail server inside the
fence before the change and waits briefly for one more after it. One more is credited,
`probe.password-change-notified`. None is not a finding: the app may tell people some other way, such as a message
in the app, so it is not assessed and the owner is asked. With no mail server in the run, it is not assessed and says
so.

`docs/REQUIREMENTS.md` marks the two that are only ever credited "credited only", as it already marks the ones
that are only ever findings "found failing only", so the list does not suggest they can mark a requirement as needing
attention.

A change taken with a wrong current password is already a finding, and after it the password is no longer the one the
check knows; both V7.4.3 and V6.3.7 are then not assessed and say why.

**A crash is still not a refusal.** A second session that crashes after the change would read as shut, so
`bystander-after` is listed in `RESTS_ON_A_REFUSAL`. The crash sweep only tried rules some setup found at fault, and
the two new rules are never findings, so it could not have caught that entry missing. It now also tries the rules
listed in `ONLY_CREDITED` (in the test) that a setup leaves open, and one setup now keeps other sessions after a
change and sends no email. The list is kept in the test rather than read from `RESTS_ON_A_REFUSAL`: read from there, a
missing entry would also have hidden the rule from the sweep, which is how the first attempt failed to catch it. The
sweep does not flag every credit that appears only with a crash: when a crash hides one flaw, checks the flaw had
stopped go on to pass on their own requests, and that is right.

**The two-factor timing tests.** They put the clock a set number of seconds before a 30-second boundary at the start
of the whole run, so every request added to an earlier check moved the boundary, and the new ones broke two of them.
They now find where the two-factor check starts in a first run and place the boundary from there in a second, and
assert it landed where they meant it to.

Broken on purpose nine ways, each caught by the test written for it: a second session left open credited, the
control before the change left out, no new email credited, no mail server read as no email, a wrong current password
leaving nothing open, the header finding inverted, the header not sent, pages open to strangers asked with a header,
and `bystander-after` left out of `RESTS_ON_A_REFUSAL` (caught by the sweep once it tried credit-only rules). The
mutations were run against `sv-check`'s own tests.

**Not done here.** The check does not look at the change page for an offer to end other sessions, or read what the
email says; any email to the account after the change counts. It does not try a header naming another user than the
first, or headers a proxy adds under other names.
