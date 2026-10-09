# A signed-in page that sets the session cookie again (9 October 2026)



From the running-app checks' review of 3 October 2026, part 3
(`docs/backlog/0029-the-running-app-checks-reviewed-on-3-october-2026-one-fault.md`), whose done note left two things
open: the cookies a signed-in page sets, and pages the run does not ask for.

**The cookies a signed-in page sets.** `probe.session-cookie-attributes` judged HttpOnly and SameSite on the cookies
the sign-in answer set, and nowhere else. An app whose sessions slide sets the session cookie again on every page, and
a browser keeps whichever it was given last: a page that sets it again without the attributes leaves the session
cookie without them from then on, while the sign-in answer, the only one judged, looked right. `private_page_checks`
already opens each private page with the signed-in session; it now reads the `Set-Cookie` headers on those answers.
A cookie that was shown to carry the session (set at sign-in, with the page refused without it,
`sign_in_cookies_carry_session`) is held to HttpOnly and SameSite as at sign-in. A page that sets it again without
either is a finding under the same rule, naming the page and what it lacks; one that keeps both is said in the run's
steps. Cookies not shown to carry the session are not judged, since HttpOnly is asked of session cookies, and so is
nothing when which cookie carries the session was not shown either way. A cookie set to an empty value, which clears
it, is not judged: it leaves nothing to protect. Sign-in's own credit stands, scoped as before to the cookies sign-in
set; a finding from a page outranks it in the report, as every finding outranks every credit.

**Pages the run does not ask for.** Not built, and not buildable: a page nobody asks for gives no answer to judge.
The credit for the four headers already names the pages it covers.

The fake app gained three switches for `/account`: setting the session cookie again with its attributes, setting it
again with nothing but a path, and clearing it.

Tests: four in `crates/sv-check/src/signed_in/page_cookie_tests.rs`. A page that sets the session again bare is found,
naming `/account` and both attributes, and every other finding and credit is as on the correct app; one that keeps
the attributes is said in the steps and not found; with the same session and page, only a cookie shown to carry the
session is judged (shown: one finding; shown not to, or not shown: none); and a page that clears it is not judged.
Six guards broken in turn, each caught: nothing judged (2 tests), every sign-in cookie judged whether or not it was
shown to carry the session (1), HttpOnly not asked (1), SameSite not asked (1), what was shown not passed to the check
(2), and a cleared cookie judged (1). The last needed a test of its own: the first run of the breaks went red in none,
since no fixture cleared the cookie on a private page.
