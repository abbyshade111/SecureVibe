# A fresh sign-in after the `--slow` wait (4 October 2026)

On family-hub, 3 October, `sv run --slow` waited out the 15-minute idle timeout (and credited V7.3.1), then went on
asking with the session A had signed in with before the wait. That session had sat unused for the whole wait, so the
app had ended it: "A signed out (400)", the owned record and the browser checks failed where a normal run minutes
before had passed them (BACKLOG, the family-hub list, item 8). The timeout check itself was never at fault: it signs
in two sessions of its own, one left alone and one kept busy, and reads only those. A's main session was the one
left behind.

`session_timeout_checks` now says whether it waited, and when it did, A signs in afresh, through the sign-in page
as before, so a form token comes with the new session and later forms fetch theirs against it. The new session is
shown to open the private page, as the first one was; every check after that uses it. When that sign-in gets no
answer, or the new session does not open the page, the run stops there, as it does when the first sign-in fails,
and says why in the report: the checks that needed a working session were not run rather than run with one the
app may have ended. That last part matters beyond lost credits: with the dead session, the sign-out check read the
app's refusal after sign-out as the sign-out working, and credited it.

The tests use the fake app's clock, which `wait` moves on rather than sleeping, with sessions that end after 15
idle minutes. A correct app run with `--slow` now earns every credit the same app earns without it, seeded and
through sign-up; an app that stops accepting sign-ins during the wait leaves the rest not assessed, with the reason,
and credits nothing that needed A. With the fresh sign-in turned off, both tests failed: the seeded slow run lost
six credits (another user's records, cross-site requests, two private-page checks, the sign-out link, and a skipped
flow step), and the run with sign-ins refused credited the sign-out with no working session. No test caught it
before these two.
