# The session cookie a signed-in page sets again (9 October)

Backlog 0029, part 3, left one thing open when the security headers were first asked of every page the run opens:
"the cookies a signed-in page sets, which `probe.session-cookie-attributes` already judges at sign-in". Many apps
set the session cookie again on later pages, to refresh its expiry or to rotate its value. Whatever a page sets is
the session from then on, so a page that sets it without HttpOnly or SameSite undoes what sign-in did right, and
until now the report credited V3.3.2 and V3.3.4 from the sign-in alone.

**What is asked.** Each private page the signed-in run opens (`[stack.run.users] private`) is already read for its
headers. Now its `Set-Cookie` lines are read too. A cookie with the name of one sign-in set is the session cookie
set again, and it is judged exactly as sign-in's is: HttpOnly, and SameSite of any value. A page that drops either is
a finding under `probe.session-cookie-attributes`, naming the page, the cookie, and what is missing, and the credit
sign-in earned is withdrawn, since a finding and a credit for the same cookie cannot both be true. (The report
already ranks a finding above every credit; withdrawing it keeps the list of what was verified honest too.) The run's
steps say which pages set the session cookie again, whether or not anything was wrong with them.

**What is left out, on purpose.**
- A cookie of another name: it does not carry the session, and judging it would turn a preference cookie into a
  session finding.
- A session cookie being deleted: an empty value, `Max-Age` of zero or less, or an `Expires` in 1970. A browser
  told to forget a cookie keeps nothing to protect.
- Pages the run does not open, as before. Only the pages named in `private` are read.

This is not a new decision: the standard is the one sign-in's cookie is held to, applied to more of the app's
answers, and the credit follows the rule the headers already follow, that it needs every page judged to pass.

**Tests** (`crates/sv-check/src/signed_in/page_cookie_tests.rs`), against the fake app with a new switch,
`account_set_cookie`, that makes its account page set a cookie: the same app setting nothing is credited (the
control); the session cookie set again without HttpOnly, without SameSite, or without both is one finding naming
`/account`, with sign-in's credit withdrawn and the step recorded; and the session cookie set again with both, another
cookie set bare, and the session cookie deleted three ways each leave the credit standing. Seven guards were broken
in turn: judging every cookie, judging either kind of deletion, judging an empty value, keeping the credit, and
skipping either attribute. Each was caught by the test written for it.
