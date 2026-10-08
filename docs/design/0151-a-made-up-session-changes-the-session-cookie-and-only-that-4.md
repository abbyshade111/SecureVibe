# A made-up session changes the session cookie, and only that (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H14) found the check for V7.2.1, whether the app checks the
session value it is sent, altering whichever cookie the browser happened to hold first and sending it alone. On an app
that sets an anti-forgery cookie on its sign-in page, that first cookie is the anti-forgery one: the request then
carried no session at all, any app refuses that, and the refusal was credited, including on an app that would believe
any session value.

The check now gives a made-up value, of the same length, to each cookie the app set at sign-in, the ones the run
already treats as the session, and sends every other cookie as it was, so the request differs from the real one in the
session alone. The real session is sent first, as a control, and a refusal is credited only when that has just opened
the same page. When sign-in set no cookie, or also gave a token that may be what carries the session, the check is not
assessed and says why, where before it altered whatever it found.

Tested with the in-memory app given a cookie on its sign-in page before the session cookie, and, separately, refusing
any request without it: an app believing any session value is found both ways, and a correct one is credited both
ways. Five guards broken in turn, each caught: altering the first cookie instead (the old behavior) and dropping the
other cookies were each caught by both new tests; skipping the control, ignoring a token, and staying silent when
sign-in set no cookie were caught by the test that drives the check directly, since the in-memory app never gives
those cases.
