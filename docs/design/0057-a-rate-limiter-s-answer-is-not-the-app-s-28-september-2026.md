# A rate limiter's answer is not the app's (28 September 2026)

Reported by an agent in another project integrating `sv`: a critical finding it listed as "F-0001" had
got HTTP 429 from the app's rate limiter, not an answer from the app. That report is not in this
repository, and nothing in `sv` matches its name at critical, so F-0001 itself is still open. Looking
for it found the fault it pointed at. The signed-in checks read an answer through `ok()` (2xx) and
`accepted()` (2xx and 3xx), and read everything else as the app refusing. A 429 is not a refusal: the
request never reached the check it was asking about. So `probe.private-page-anonymous` credited V8.2.1,
"refused to somebody not signed in", when a limiter had answered the stranger. The same misreading
runs the other way too: `probe.sign-out-on-get` reads the private page being refused after a GET to
the sign-out address as the session having ended, and a limiter answering that look reported a sign-out
that never happened. There are about thirty places where these checks read an answer, and each reads
it its own way.

**The fix is where every request passes, not at the thirty places.** `run_with` now sends through
`Patient`, which wraps the app. When the answer is a rate limiter's, a 429, or a 503 with `Retry-After`
(a 503 that names no wait is the app failing, and is left as it was), it waits what the app asks, at
most a minute, five seconds when it names none or names a date, and sends the request once more.
Not for a request whose id says it is a guess: the guessing checks send wrong passwords and codes on
purpose to see the limiter answer, and a wait would change what they measure and send one guess more
than they count. Their follow-ups keep the word too, such as the right code after the guesses
(`…-after-guesses`), so a lockout is read exactly as before. The wait goes through `Http::wait`, so
the tests' fake app moves its clock rather than sleeping, and the two-factor checks, which read that
same clock, see the time pass.

**When the limiter is still answering after the wait,** no refusal in the run can be told from the
limiter's. So nothing the run would have credited is credited: each credit becomes not assessed,
saying what it would have been and naming the requests the limiter kept answering. Findings stay,
since hiding a real one is the worse fault, and the run adds that one resting on a refusal may be the
limiter's, under the findings' own requirement ids. Withdrawing every credit rather than only those
the limited requests touched is deliberately coarse: no record says which conclusion rests on which
request, and a limiter that will not let up after the wait it asked for is a run to repeat.

**Not changed, and entries of their own:** a 500 from the app is still read as a refusal where the
checks read `!ok()`, which can credit the same V8.2.1 when the private page crashes for a stranger;
and the anonymous probes outside `signed_in/` (`probes.rs`, `running.rs`) read answers without this
wrapper, though the ones read here only ever raise a finding, and each needs a 2xx to do so.

**Broken on purpose nine ways**, each restored from the bytes read before it: never waiting a limit
out, caught by six tests; waiting out guesses too, eight (the guessing checks' own tests among them);
a persistent limit withdrawing nothing, three; no word about the findings, two; a 503 without
`Retry-After` counted as a limiter, two; `Retry-After` ignored, four; no cap on the wait, two; resending
without waiting, four; a limit still answering not recorded, three. The first pass had four of these
caught by one test each; a real finding kept through a persistent limit (a default admin account,
found by signing in, which the limiter did not touch), nothing credited in the sign-out case, and a
direct test of what counts as a limiter were added for them.


**Later, 29 September 2026: the anonymous questions, and a limit on all the waiting.** The paragraph above says the
anonymous probes read here only ever raise a finding, each needing a 2xx. Reading each one showed two that do not:
`security_headers` judges any answer on `/`, so a limiter's 429 page without the app's headers is a Medium finding
the app does not deserve, and `probes::verified` credits "source control not exposed" when `/.git/HEAD` and
`/.git/config` merely answered, so two 429s earned it. Both are witnessed in a test.

So the anonymous questions go through the same `Patient`, by `signed_in::ask_anonymously`, called from step 4 of the
run in `sv-run`. An answer the limiter was still giving after the wait is left out of `probe_responses`, as a request
that got no answer is, since every reader of those answers (`probes::evaluate`, `probes::verified`,
`probes::evaluate_api`, `running::evaluate`) judges what it is given as the app's. Leaving it out is enough: each
reader already credits nothing from a missing answer. The requests left out travel in `RunOutcome::probes_rate_limited`,
and `sv run` and the report say which they were, as a gap ("the app's rate limiter answered them in its place"),
rather than counting them among the questions that got no answer at all.

`Patient` also now stops waiting after five minutes in all (`MOST_WAITING`). Each wait was already at most a minute,
but a limiter answering every request would have held a run up for a minute a request; past five minutes a limited
answer is recorded as the limiter's without waiting, and says so.

Broken on purpose four ways, each caught: keeping the limiter's page among the answers, not waiting for the anonymous
questions, no limit on all the waiting, and the report's gap never said. Not tested end to end: no test here starts a
real app behind a rate limiter, so the wiring in `sv-run` is checked by the compiler and by reading, not by a run. The
sign-in provider (`oidc.rs`) and MCP server (`mcp_server.rs`) checks were not looked at for the same reading.

### Later, 5 October 2026: a sign-in the app's limit refuses is named, and the spec says how many there are

Found by session paper-facts in the loop trials, and trial 3 before them: an app that limits sign-in attempts, as it
should, answered `sv`'s admin sign-in with 429, and the signed-in checks had nothing to work with. The report said so
only as a list of request ids under each credit it withheld, and when the refused sign-in was the first user's, it said
the sign-in request, the accounts, or the page was "not what securevibe.toml says", which sent the builder looking for
a mistake that was not there. The owner chose both fixes on 5 October.

- **The spec states the number.** `[stack.run.users]` now says `sv` signs in up to 60 times in one run, all from one
  address, a few of them on purpose with a wrong password, and last of all the guessing check's wrong passwords
  (`failed-sign-ins` plus two). A builder can let the test copy allow that many and keep the real limit everywhere else.
  The number is `SIGN_INS_IN_A_RUN`. A test counts every request sent to the sign-in path, other than the page's GET,
  in each of the seven scripted runs (13 to 50; repeats under one id counted, since each is an attempt to an app's
  limit), holds each to the number, checks that the guessing check's attempts come after all the others, and checks
  that the spec gives the same number.
- **A refused sign-in is named, once.** `Patient` now knows the sign-in path and, when the limiter is still answering a
  request sent to it after the wait, notes it as a refused sign-in. The run then adds one gap naming those sign-ins,
  saying it is the limit working, not the app failing the checks or securevibe.toml being wrong, and what to change.
  It is listed under the requirements whose credit was withheld, and under the first user's checks when that sign-in
  was the one refused.
- **The first user's sign-in refused by the limit no longer reads as a mistake in securevibe.toml.** `SignedIn` carries
  whether its answer was the limiter's; when it was, the run stops as before but leaves the saying to that one gap.

What did not change: every credit is still withheld while the limiter keeps answering anything, sign-ins included. A
sign-in refused by the limiter can look exactly like the refusal a check is waiting for (the old password refused
after a change), so the blanket rule is what keeps that from being credited.

Broken on purpose nine ways, each caught by a test written for it: no sign-in ever noted, the sign-in page's GET
counted as a sign-in, any request other than GET counted, the first user's limited sign-in treated as a manifest
mistake (twice: the flag ignored, and never set), the first user's checks left out of the gap, the number lowered
below what a run makes, the spec's number different from the code's, and the gap left empty. Not tested end to end:
no test here starts a real app with a limit on sign-ins, and 60 is measured against the scripted runs, not every
combination of settings an app can list.
