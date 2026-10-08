# A crash is not a refusal (29 September 2026)

The signed-in checks read any answer that is not 2xx as the app refusing. A 429 from a rate limiter was the first
case found (see "A rate limiter's answer is not the app's"); a crash is the other. A private page that fails with a
500 for somebody not signed in was credited as refused to them (V8.2.1), and the same reading is in 29 places that
credit a pass because something was refused: another user's record, the admin page, a short password at sign-up, a
session after sign-out, a reused code, an oversized upload, and the rest. A crash, or no answer at all, says nothing
about whether the app would have let the request through.

**What changed.** `Patient`, which every signed-in request already goes through, records each request answered with a
5xx (a rate limiter's 503 aside) or not answered at all. `RESTS_ON_A_REFUSAL` names, for each pass that is credited
because something was refused, the requests whose refusal earns it: an id, the page fetched first for its form's
token (`signup-short-page`), or the start of a family of ids (`guess-`, `totp-3-`). When the run is over, a pass one
of whose requests crashed moves to not assessed, naming the requests and their status, and the owner is told to fix
the error and run again. Passes that rest on no crashed request stay, and findings are untouched. This is narrower
than the rate limiter's rule, which withholds every pass in the run, because a crash is the app's own answer to one
request and says nothing about the others.

**How the list was checked.** Writing it by reading the code was not enough. The test
`a_crash_never_turns_a_finding_into_a_pass` runs the scripted app in six setups with flaws switched on, and for each
setup crashes every request a normal run sends, one at a time, failing when a rule that was found at fault comes back
credited. The first list passed the existing 247 tests and failed this one on requests of five kinds: the sign-up form's page fetch
(a crash there means nothing was signed up, so the short password "was refused"), signing in as A or B before their
checks, the sign-in before each two-factor code, the right code sent after the guesses, and a request in the password
change check. The test also fails when a listed rule is not found at fault in any setup, since a rule never tried is
not checked. It sends about 1,100 runs and takes about 75 seconds in a test build (11 in a release build); it spreads
them over the machine's processors.

Broken on purpose six ways, each caught: nothing withheld, the private page left out of the list, a 5xx not recorded,
no answer not recorded, the form page not counted with its request, and the sign-in of A left out for the admin page.
These were run against `sv-check`'s own tests rather than the whole workspace, since the change is contained there.

**Not done here.** Three findings are raised from a refusal in the same way, so a crash can raise them falsely:
signing out by a plain link (`SIGN_OUT_ON_GET`, from `private-after-get-logout`), the composition rules and the long
password (`COMPOSITION_RULES`, `LONG_PASSWORD`, from a strong or long password that did not work). They are their
own backlog item. The anonymous probes and the sign-in provider and MCP checks were not looked at for a crash read as
a refusal.

**Later the same day: findings raised from a crash.** The other direction. A correct app, each request crashed in
turn, raised five findings it did not deserve: signing out by a plain link (`SIGN_OUT_ON_GET`: the page after it
failed, read as the session ended), the composition rules and the long password (`COMPOSITION_RULES`,
`LONG_PASSWORD`: a sign-up with a lowercase or long password that failed, read as refused), the reset form revealing
accounts (`RESET_REVEALS_ACCOUNT`: a reset for nobody that failed, read as answered differently from a real one), and
the wrong-password limit (`NO_BRUTE_FORCE_LIMIT`: a guess that failed may never have been counted, so the limit
seemed not to hold). The backlog entry named the first three; the sweep found the last two. `RAISED_ON_A_REFUSAL`
names each finding's requests, and a finding one of whose requests crashed moves to not assessed, naming them, as a
pass does.

`a_crash_on_a_correct_app_raises_no_finding` holds it without trusting the list: it runs a correct app in three setups
(signed up with a limit on wrong passwords; a private WebSocket and uploads; slow, with sessions that end), asserts
nothing is found before anything crashes, then crashes each request, one at a time, and fails on any finding at all.
A finding raised from a crash that is not listed is caught the same way as one that is. It takes about 55 seconds in a
test build. Each of the five rows, removed in turn, turns it red, and so does keeping every finding; a direct test (`a_page_that_crashes_after_a_plain_sign_out_link_is_not_reported_as_signed_out`) also catches that, and catches dropping every finding, which the sweep cannot see.
