# Policy numbers, and the one requirement they make checkable

V6.3.1 is at level 1 and asks that brute-force controls are implemented *according to the
application's security documentation*. Nothing can check behavior against prose. A number is
different: `failed-sign-ins` under `[policy]` in securevibe.toml is the owner stating the policy,
and a running app can be held to it.

The probe makes one more wrong attempt than the stated number and watches what changes. Pushing back
is read broadly — a different status on the last attempt than the first, a refusal (429, 423, or no
answer at all), or an attempt that takes markedly longer. Narrowing it would report apps that defend
themselves in a way this did not anticipate, and a check that cries wolf is one people learn to skip.

### Held to the stated number, not to having any limiter at all

An app that only gives way after twenty attempts, where the owner said three, has not implemented the
policy. Accepting any limiter would stop the check from checking the claim, which is the only thing
it is for; `an_app_that_pushes_back_too_late_is_still_a_finding` holds that.

The window (`within-minutes`) is recorded and **not** tested: every attempt this makes lands within a
few seconds, which is inside any window worth stating. The count is the testable half, and the
evidence says so in the words the report prints.

### Three ways it refuses to run

- **No number stated** — *not assessed*, naming the setting that would settle it. An app nobody has
  stated a policy for is not thereby failing, and certainly not passing.
- **Zero** — refused rather than read as one. Nobody means "refuse the first attempt anybody makes",
  and guessing they meant one holds the app to a policy the owner did not state.
- **Twenty-five or more** — refused, because one check must not turn into thousands of requests
  against somebody's app.

### It runs last, and never guesses at the test users

This is the only check that deliberately provokes the app into refusing requests. A limiter that
counts by address rather than by account would then be refusing every other check's requests too, and
the run would start reporting faults of this check's own making. So it runs after everything else,
and it guesses at an account it made through `signup` — or, where there is no sign-up, at a name no
account has, which exercises an address-based limiter only. The report says which was used, because
the two are not the same evidence.

A clean result is *checked*, not a pass: the app pushed back at the stated number on one run.

### A limit that believes a made-up address (V15.3.4)

Once the brute-force check has seen the app refuse — with a different answer, not only a slower one,
because a delay is too noisy to compare — two more wrong attempts follow. The first claims to come
from `203.0.113.77`, an address set aside for documentation, in `X-Forwarded-For`, `X-Real-IP`, and
`Forwarded`; the second claims nothing. The first answered as the very first attempt was, while the
second is still refused, is a limiter that let a header the client wrote lift it. Nothing sits in
front of the app inside the fence, so no proxy can have written that header.

The second attempt is the control: a limit that lifts by itself lifts for both, and blaming the header
for it would be a false finding. It is only ever a finding. A limit counting by account is not moved
by the header at all, which says nothing about how the app treats addresses.

It is asked against the running app rather than the live site, where it was first listed: `sv probe`
sends only read-only requests, so it cannot make wrong sign-in attempts. And one limit on it, found
writing the tests: a limit counting by address, set lower than the longest run of wrong sign-ins the
suite makes before the brute-force check (four in a row, trying default accounts), trips during the
suite. The brute-force check then finds the app already refusing, says so, and asks nothing, this
included. That is the honest outcome, and against such an app V15.3.4 stays unasked.

Five breaks, each caught: no control, the header never sent, run on a slowdown too, "lifted" misread,
and the check never run.


**Two of each, after review.** The first version sent one attempt claiming an address and one claiming
nothing. A limiter that lets one attempt through for each one it refuses — a token bucket, a sliding
window, `nginx limit_req` — answers that pair in exactly the pattern of a limit believing the header,
so a correct app was reported, with an evidence line word for word the true one's. Now two attempts
claim two different addresses and two claim nothing, and it is a finding only when both claimed ones
got through and both plain ones were refused. The fake app has both kinds of leak: one attempt per
refusal (`lockout_leaks`), which the plain pair catches, and a window that rolls over just as the first
claimed attempt arrives (`window_rolls_over_at_first_claim`), which only the second claimed attempt,
from its own address, catches. Alternating plain and claimed attempts would not have worked: a
one-for-one leak produces exactly that alternation. A leaky limiter can still hide an app that does
trust the header; that is the safe direction for a check that is only ever a finding.
### Two-factor codes, computed rather than waited for (V6.5.1, V6.5.5)

A `totp` entry names the code step of a two-factor sign-in. `seed` is given a third account —
`SV_USER_TOTP`, `SV_PASSWORD_TOTP` — and `SV_TOTP_SECRET`, 20 random bytes in base32, to enroll it
with. Never A or B: every other check needs them to sign in with a password alone. With the secret
known, `sv` computes the codes an authenticator app would show (RFC 6238, through the RustCrypto
`hmac` and `sha1` crates, and held to the RFC's own test values), so a code from minutes ago is a
calculation. That is what lets V6.5.5 be asked without the slow mode it was thought to need.

The order is the substance, and the first order was wrong. It used the current code, then the same
code again, then the old one — and many apps refuse a code for any step not later than the last one
used, which is how they stop a code working twice. After a current code, that rule refuses an old
one whatever its age, so an app taking ten-minute-old codes was credited with V6.5.5. The fake app
does exactly this, and the test for an app that accepts any age failed; so the old code, five steps
back, now goes first, before any code has been used. Then the current code, which has to sign in;
then that code again; then, after waiting for the next step to begin, a fresh code, which has to sign
in too, or the refusals before it may be the account locking and nothing is credited. And before the
first code, the private page has to stay shut with the password alone, or codes are not what lets
anybody in.

Six breaks, each caught: the old code moved back after the control (three tests), a credit without
the fresh control, no gate, no wait, the old code only one step back, and reuse never found.


**The clock, after review.** The step was read once, at the top, and the current code used twice
several sign-ins later. When the 30-second step ended in between — ordinary, since a run starts
anywhere in a step — an app that takes only the current step refused the second use because the code
was stale, and a reuse flaw was credited as absent. Found in review with a fake clock that moves with
every request. Now the check waits out a step's last ten seconds before starting, looks at the clock
again after the second use, and when the step has moved on and the code was refused, tries the pair
once more with the new step's code; a step that ends twice leaves V6.5.1 not assessed. A control code
refused as its step ended no longer tells the owner to check their manifest. At three seconds a request
a sign-in and its second use cannot fit in one step at all, and the answer there is honestly not
assessed. The V6.5.5 credit now says what it shows — a defined lifetime, shorter than two and a half
minutes — and that the 30-second bound was not shown, since a sensible allowance for clock drift accepts
the previous step's code.
### Skipping a step (V2.3.1)

`flow` under `[stack.run.users]` names a flow of several steps — a checkout, a sign-up with a
confirmation — and `completed`, words the last step answers with only when the whole thing finished,
in the page or in the address it sends the browser on to. A goes through every step in order first,
and that has to end in `completed`: an app whose flow does not work as described refuses every skip,
and that is not a guarded flow. Then B, signed in afresh each time so nothing carries over, goes
straight to the last step, and — when there is a middle to leave out — does the first step and then
the last. Either ending in `completed` is a finding; both refused supports V2.3.1, which stays on
`manualOnly` at the owner's word, since two skips refused is not every order refused. Doing a step
twice, and the wrong order other than by leaving steps out, were not tried until 7 October 2026 (below).

Only an answer the app accepted counts as finished, and only because of the owner's words. Both
halves have a case of their own: an error page saying "an order is placed only after the steps before
it" is a refusal, and so is a `303` back to the first step, which is an accepted status and the way
many apps answer a skipped step. That second case was added after the first run of breaks: judging a
skip by its status alone was caught by nothing until it existed.

**Later, 7 October 2026: a step done twice, and the wrong order.** The owner's answer of 27 September,
that "trying a repeated step is the way to strengthen it", is now built. With a middle to the flow, B
tries two more orders, each in a fresh session, and each one leaves out no step by count or by name:

- **The steps between the first and the last, then the first, then the last.** An app that asks only
  whether each step was ever done, not in which order, finishes it.
- **The first step once for each step before the last, then the last.** An app that counts the steps
  taken rather than knowing which they were finishes it.

Either ending in `completed` is the same finding as a skip, now titled "The flow can be finished
without its steps in order"; all four tries refused is support for V2.3.1 and no more. A two-step flow
has no middle, and each of these would be the steps in order, so it still gets the one skip.

**The order of the tries is a guard.** An app may keep where each person is in the flow against the
account rather than the session, and then a fresh session does not start B afresh. Every try with
the first step in it can leave such an app holding B at the second step, after which the middle sent
first is simply the next step. Built in the order first written, the correct fake app was reported:
the skip past the middle left B at step two, and the wrong order then finished. So the wrong order now
goes straight after the skip to the last step, which leaves a correct app where it found it.

**Not tried, on purpose: the last step sent again after the flow finished.** An app's answer cannot
tell an order placed again from the same order shown again, the false alarm `probe.action-done-twice`
had before the owner's decision of 5 October 2026 ("Later, 5 October 2026: two users, not one"). B
has finished no flow when it tries these, so a wrong order ending in `completed` cannot be that. The
hand check now says the other orders, and the last step again, are still the owner's.

Five guards broken in turn, each caught: either new order left out, a two-step flow given them too,
and the wrong order moved after the skip past the middle (which turns 36 tests red, the correct app's
among them). The fifth, the first step sent once too few times, was caught by nothing at first: the
counting fake app keeps its count against the account, and a step left over from the try before made
up the difference. A test now reads the app's own record of what each try sent.

### The admin page, as support for V8.3.1

V8.3.1 asks that access rules are enforced on the server, at a layer the browser cannot get round,
not only by hiding buttons. The admin-page probe already shows part of that: signed in as an
ordinary user, it asks for each admin page directly, and the server refuses while the admin's own
session opens it. The owner's decision, 27 September 2026, was to let that count as **supporting
evidence only**, and V8.3.1 went on `manualOnly` for it. One page refused is not every rule enforced
on the server, and actions sent straight to an API are not tried, so the refusal stands beside the
owner's answer to the design question and strengthens it, without settling it. An admin page that
opens to an ordinary user is a finding against V8.3.1 as well as V8.2.1, because that shows the
rule is not enforced on the server.

Seven breaks, each caught: any status counting as finished, no control, the middle never skipped, a
skip judged by status alone, the redirect address ignored, a working skip credited, and a one-step
flow tried anyway. The flow is also in the default test fixture, so every signed-in test runs it and
the checks after it are shown not to be disturbed by it.

### Admin actions, sent straight to the app (27 September 2026)

The owner gave two reasons the admin page is only support for V8.3.1: one page refused is not every
rule enforced, and nothing was ever sent straight to the app's API. This answers the second.
`[[stack.run.users.admin-actions]]` lists requests only an admin should be able to make, in the same
shape as every other request there, and each is sent twice: by the first ordinary user, then by the
admin.

**What decides the outcome is the action's effect, not its status.** Many apps answer a refused form
with a redirect to the sign-in page, and a successful one with a redirect too. Some answer a refusal
with 200. So each request carries a marker of its own (`{marker}`), and `check` names a page, read by
the admin, where the marker shows once the action has been done. The ordinary user's marker on that
page is a finding. The admin's marker, with the ordinary user's absent, is a refusal confirmed by its
control. Neither marker there means the admin could not do it either, and the refusal says nothing.
Without `check`, only a success status to the ordinary user is reported, at medium confidence and
saying it was judged by status alone, and nothing is credited, because a refusal cannot be told from a
request that did nothing.

**Both sessions are shown signed in first**, by opening a private page with each. This was found by
building it, not by planning it: the probe first ran after the password-change checks, and with a
seed and no sign-up those change the first user's own password. Sign-in reports what it sent, not
whether it worked, so the ordinary user was signed out without anything saying so. Signed out, the
ordinary user was refused, by a correct app and by an open one alike, and the correct app's refusal was
credited for the wrong reason. It came to light only because the test for the open app found nothing.
The probe now runs before the password changes, and the signed-in guard has a witness of its own: the
same call with the ordinary user's password wrong in the app credits nothing, and with it right
credits the refusal.

**What it earns.** A refused action cites V8.2.1 and V8.3.1, like the admin page, and V8.3.1 stays on
`manualOnly`: the actions are a sample the owner chose, which is the owner's first reason, and still
stands. An action the ordinary user got done is a finding against both.

Broken on purpose, six ways, each caught by its own test: the admin control removed, the ordinary
user's marker never looked for, the signed-in guard off, a status-only success not reported, a
refusal with no `check` credited, and the manifest's rule that a `check` needs a `{marker}` switched
off. The fifth was first recorded as caught by nothing. It was a mutation that did not compile, which
the break script read as green, because `cargo test` exits the same way for a build error as for a
failing test. The script now tells the two apart, and the corrected mutation is caught.

### A role written into the sign-up form (27 September 2026)

V8.3.1's own example of an authorization decision the client can manipulate is a role the browser
sends. The commonest way it happens in a small app is mass assignment (V15.3.3): sign-up copies every
field of the request onto the new account, so `role=admin` in the form makes an admin.

With `signup` and an `admin` page, the probe makes two accounts through the app's own sign-up. One is
plain. The other's request also carries `role=admin`, `roles=admin`, `is_admin=true`, `isAdmin=true`,
and `admin=true`, added to a copy of the owner's own sign-up request, so a JSON sign-up gets them in
its JSON and one that emails an activation code is activated the usual way. The values are text,
because a template's values are text; most frameworks read `"true"` as true, and one that does not
is a gap this probe does not close.

Both accounts are shown signed in by opening a private page before either asks for anything, the
lesson of the admin actions. Then each asks for every admin page. A page that opens to the second and
not to the first opened because of a field the browser sent, which is a critical finding against
V8.3.1 and V15.3.3. A page the plain account opens too is left to the admin-page check, whose finding
it is. A refusal credits nothing: five guessed names refused say nothing about a sixth. The check is
recorded as having run, with no requirement, as SECURITY.md's is.

Broken on purpose, five ways, each caught: the signed-in guard off (a sign-up that makes nobody
would then read as a refusal), the plain control not consulted (an admin page open to everybody
would be blamed on the role field), the fields never added, the finding not raised, and the credit
given a requirement.

### Two more passwords at sign-up: one far down the list, one made from your own words

The password checks already sign up with a control — an ordinary strong password that has to work
before anything else means anything — and then with passwords that each differ from it in one thing.
Two more join them, each with a twin of its own: a random password of exactly the same shape, every
letter a random letter and every digit a random digit. A refusal counts only when the twin was
accepted, because a refusal the twin shares is about the shape (a composition rule, a length rule),
not about the password.

**V6.2.12, breached passwords.** `1qaz2wsx3edc4rfv`, at line 12,393 of
`data/knowledge/common-passwords.txt`: well past the top 3000 that V6.2.4 asks about, so an app that
checks only those accepts it, and 16 characters, so no length rule up to 16 refuses it first. Two
things limit what it can say, and both are said:

* **The list's source is not recorded in this repository**, so the password's being breached is not
  taken from it. It is Have I Been Pwned's count: the Pwned Passwords range for the first five
  characters of its SHA-1 hash, which says it has been seen **133,732 times**. The owner first
  fetched the range in a browser on 26 September 2026, because the network policy refused it from
  the session; `tools/pwned_passwords.py` now re-fetches it and rewrites
  `data/breached-password-evidence.json` with the matching line, the hash, the count, and the date.
  That file is compiled into `sv`, which fetches nothing, and the finding's wording is built from it:
  "seen in breaches 133,732 times when last checked, on 26 September 2026". A test holds the password
  to the file and the hash to the password, so the password cannot change without new evidence, and
  the script refuses to write if the password ever drops out of the data. Only the first five
  characters of the hash are sent, with `Add-Padding: true`.
* **The list is breach data, as far as a sample can say.** The same script's `--sample` looked up
  300 entries of `common-passwords.txt` on 26 September 2026, 50 evenly spaced in each of six bands
  of rank (1–1,000, to 3,000, 10,000, 30,000, 60,000, and the end at 96,517). **All 300 are in Pwned
  Passwords.** The counts fall with rank, as a list ordered by frequency should: a median of 391,080
  sightings in the top thousand, 43,108 in ranks 3,001–10,000, and 8,932 in the last band, with the
  fewest, 11, in ranks 30,001–60,000. The entries and counts are in
  `data/common-passwords-breach-sample.json`. This says the list is breach data, not where it came
  from, which stays unrecorded; and it is a sample, not the whole list. The list is v1's too, so it
  was only read.
* **V6.2.12 is on `manualOnly`** in `data/knowledge/applicability.json`, the list v1 shares. A
  refusal is therefore *supporting* evidence, never *checked*, and that is left alone on purpose:
  one refused password shows that a list longer than 3000 is checked, not that it is a set of
  breached passwords, and the list is v1's too. An acceptance is still a finding.

**V6.2.11, context-specific words.** The requirement asks that *the documented list* is used, so the
list is the owner's, as a policy: `[policy] context-words = ["acme", "notes"]`. The first word with
between 4 and 32 letters or digits is lowercased and repeated past 16 characters. With no list, or no
usable word on it, V6.2.11 is *not assessed* and says how to list them: guessing at words — the app's
name, say — would be testing a list nobody wrote. The v1 template refuses a password containing the
app's name, compared without case, which is the same rule seen from the other side.

Seven breaks, each caught: an accepted password credited (for each rule), a refusal credited without
its twin (for each rule), a list guessed when none was given, one-letter words tried, and a twin
that was really the password itself.
